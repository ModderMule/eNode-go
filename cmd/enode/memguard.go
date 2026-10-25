package main

import (
	"enode/admin"
	"enode/memguard"
	"enode/meta"
)

// registerMemoryCaches hands the memory guard the caches it may shed: the eD2K meta
// search cache, the MetaApi.Search chunk cache and the metafile cache. Each is looked
// up at every shed, since a reload can replace the meta search cache.
func registerMemoryCaches(g *memguard.Guard, searcher *meta.Searcher, api *metaAPIRuntime) {
	if searcher != nil {
		g.Register("metaSearch", func() memguard.Shedder {
			if c := searcher.SearchCache(); c != nil {
				return c
			}
			return nil
		})
		g.Register("metaApiSearch", func() memguard.Shedder {
			if c := searcher.CatalogCache(); c != nil {
				return c
			}
			return nil
		})
	}
	if api != nil && api.fetcher != nil {
		g.Register("metafile", func() memguard.Shedder { return fetcherCache{api.fetcher} })
	}
}

// memoryGuardView is the guard's state for the Runtime tab.
func memoryGuardView(st memguard.Stats) *admin.MemoryGuardView {
	view := &admin.MemoryGuardView{
		Enabled:       st.Enabled,
		Limit:         st.Limit,
		Source:        st.Source,
		ShedAtPercent: st.ShedAtPercent,
		KeepPercent:   st.KeepPercent,
		LiveHeap:      st.LiveHeap,
		Sheds:         st.Sheds,
		LastShedBytes: st.LastShedBytes,
		Caches:        make([]admin.MemoryCacheView, 0, len(st.Caches)),
	}
	if !st.LastShed.IsZero() {
		view.LastShed = admin.FormatTime(st.LastShed)
	}
	for _, c := range st.Caches {
		view.Caches = append(view.Caches, admin.MemoryCacheView{Name: c.Name, Entries: c.Entries, Bytes: c.Bytes})
	}
	return view
}

// fetcherCache is the metafile cache as a memguard.Shedder.
type fetcherCache struct {
	f interface {
		ShedCache(keep float64) int64
		CacheBytes() int64
		CacheLen() int
	}
}

func (c fetcherCache) Shed(keep float64) int64 { return c.f.ShedCache(keep) }
func (c fetcherCache) Bytes() int64            { return c.f.CacheBytes() }
func (c fetcherCache) Len() int                { return c.f.CacheLen() }
