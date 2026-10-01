package storage

import (
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// eMule sends every numeric filter of its search window as >= or <= (ops 3 and 4,
// srchybrid/SearchResultsWnd.cpp:1035-1053). Only > and < were understood, so every
// size, availability, complete, bitrate and length filter was pruned and ignored.
func TestMatchSearchExprNumericOperators(t *testing.T) {
	file := File{Name: "x", Size: 100, Sources: 5, Completed: 2, Bitrate: 128, Runtime: 300}
	values := map[uint8]uint64{
		SearchTagSize: 100, SearchTagSources: 5, SearchTagComplete: 2,
		SearchTagBitrate: 128, SearchTagLength: 300,
	}
	// For each operator, whether it holds for have == v-1, v, v+1 against want v.
	ops := []struct {
		op   uint8
		name string
		want [3]bool // want = value+1, value, value-1
	}{
		{SearchOpEqual, "=", [3]bool{false, true, false}},
		{SearchOpGreater, ">", [3]bool{false, false, true}},
		{SearchOpLess, "<", [3]bool{true, false, false}},
		{SearchOpGreaterEqual, ">=", [3]bool{false, true, true}},
		{SearchOpLessEqual, "<=", [3]bool{true, true, false}},
		{SearchOpNotEqual, "<>", [3]bool{true, false, true}},
	}
	for tag, have := range values {
		for _, op := range ops {
			for i, want := range []uint64{have + 1, have, have - 1} {
				got := MatchSearchExpr(numericLeaf(tag, op.op, want), file)
				t.Logf("input: tag=%#x have=%d %s %d, output: %t", tag, have, op.name, want, got)
				if got != op.want[i] {
					t.Fatalf("tag=%#x: %d %s %d = %t, want %t", tag, have, op.name, want, got, op.want[i])
				}
			}
		}
	}
}

// An operator past 5, a multi-byte tag name, or an unstored tag carries no constraint
// the engines can apply, so it prunes rather than matching nothing.
func TestNumericConstraintRejectsUnknownForms(t *testing.T) {
	cases := []struct {
		name string
		expr *SearchExpr
	}{
		{"op 6", numericLeaf(SearchTagSize, 6, 1)},
		{"tag name length 2", &SearchExpr{Kind: SearchUInt32, TagType: 0x02000203}},
		{"rating tag 0xf7", numericLeaf(0xf7, SearchOpGreaterEqual, 1)},
	}
	for _, tc := range cases {
		_, prune := matchSearchExpr(tc.expr, File{}, "")
		sql, _ := BuildSearchWhere(tc.expr, DialectMariaDB)
		_, _, mongoPrune := mongoFilterNode(tc.expr)
		t.Logf("input: %s TagType=%#08x, output: memoryPrune=%t sql=%q mongoPrune=%t", tc.name, tc.expr.TagType, prune, sql, mongoPrune)
		if !prune || sql != "" || !mongoPrune {
			t.Fatalf("%s must prune in every engine", tc.name)
		}
	}
}

// The SQL and MongoDB renderings of each operator, so the three engines agree.
func TestNumericOperatorsSQLAndMongo(t *testing.T) {
	sqlOps := []string{"=", ">", "<", ">=", "<=", "<>"}
	mongoOps := []string{"$eq", "$gt", "$lt", "$gte", "$lte", "$ne"}
	columns := map[uint8][2]string{
		SearchTagSize:     {"f.size", "file_size"},
		SearchTagSources:  {"f.sources", "file.sources"},
		SearchTagComplete: {"f.completed", "file.completed"},
		SearchTagBitrate:  {"s.bitrate", "bitrate"},
		SearchTagLength:   {"s.length", "length"},
	}
	for tag, col := range columns {
		for op := SearchOpEqual; op <= SearchOpNotEqual; op++ {
			expr := numericLeaf(tag, op, 42)
			sql, args := BuildSearchWhere(expr, DialectMariaDB)
			filter, _, prune := mongoFilterNode(expr)
			t.Logf("input: tag=%#x op=%d, output: sql=%q args=%v mongo=%v", tag, op, sql, args, filter)

			if want := fmt.Sprintf("(%s %s ?)", col[0], sqlOps[op]); sql != want || len(args) != 1 || args[0] != uint64(42) {
				t.Fatalf("sql: got %q %v, want %q [42]", sql, args, want)
			}
			if prune {
				t.Fatal("mongo pruned a supported leaf")
			}
			cond, ok := filter[col[1]].(bson.M)
			if !ok || cond[mongoOps[op]] != uint64(42) {
				t.Fatalf("mongo: got %v, want {%s: {%s: 42}}", filter, col[1], mongoOps[op])
			}
		}
	}
}

// Artist, album and title constraints (0xd0-0xd2) were pruned. They are substring
// matches, case-insensitive, in all three engines.
func TestMediaStringConstraints(t *testing.T) {
	file := File{Name: "Snow Fight.mp3", Artist: "Jan Morgenstern", Album: "Sintel OST", Title: "Snow Fight"}
	cases := []struct {
		tagType uint32
		column  string
		value   string
		want    bool
	}{
		{searchTypeArtist, "artist", "morgenstern", true},
		{searchTypeArtist, "artist", "nobody", false},
		{searchTypeAlbum, "album", "SINTEL", true},
		{searchTypeAlbum, "album", "other", false},
		{searchTypeTitle, "title", "fight", true},
		{searchTypeTitle, "title", "50%", false},
	}
	for _, tc := range cases {
		expr := &SearchExpr{Kind: SearchString, TagType: tc.tagType, ValueString: tc.value}
		got := MatchSearchExpr(expr, file)
		sql, args := BuildSearchWhere(expr, DialectMySQL)
		filter, _, prune := mongoFilterNode(expr)
		t.Logf("input: %s=%q, output: memory=%t sql=%q args=%v mongo=%v", tc.column, tc.value, got, sql, args, filter)
		if got != tc.want {
			t.Fatalf("memory: %s %q matched=%t, want %t", tc.column, tc.value, got, tc.want)
		}
		if want := "(s." + tc.column + " LIKE ?)"; sql != want || args[0] != "%"+escapeLike(tc.value)+"%" {
			t.Fatalf("sql: got %q %v", sql, args)
		}
		if _, ok := filter[tc.column]; !ok || prune {
			t.Fatalf("mongo: got %v prune=%t", filter, prune)
		}
	}
}
