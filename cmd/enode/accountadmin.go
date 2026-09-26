package main

import (
	"context"
	"errors"

	"enode/accounts"
	"enode/admin"
	"enode/storage"
)

// accountAdmin adapts the account service to the dashboard's AccountAdmin, so the
// admin package keeps no dependency on accounts or storage.
type accountAdmin struct {
	svc *accounts.Service
}

var _ admin.AccountAdmin = accountAdmin{}

func (a accountAdmin) ListAccounts(ctx context.Context, q admin.AccountQuery) ([]admin.AccountRow, error) {
	list, err := a.svc.Store().ListAccounts(ctx,
		storage.AccountFilter{State: storage.ParseAccountState(q.State), Search: q.Search}, q.Limit, q.Offset)
	if err != nil {
		return nil, err
	}
	out := make([]admin.AccountRow, 0, len(list))
	for _, acct := range list {
		out = append(out, accountRow(acct))
	}
	return out, nil
}

func (a accountAdmin) Account(ctx context.Context, id uint64) (admin.AccountDetail, error) {
	acct, err := a.svc.Store().AccountByID(ctx, id)
	if errors.Is(err, storage.ErrAccountNotFound) {
		return admin.AccountDetail{}, admin.ErrAccountNotFound
	}
	if err != nil {
		return admin.AccountDetail{}, err
	}
	d := admin.AccountDetail{AccountRow: accountRow(acct), Steps: []admin.AccountStepRow{}, Payments: []admin.PaymentRow{}}
	recs, err := a.svc.Store().AccountSteps(ctx, id)
	if err != nil {
		return admin.AccountDetail{}, err
	}
	byID := map[string]storage.AccountStep{}
	for _, r := range recs {
		byID[r.StepID] = r
	}
	for _, step := range a.svc.Steps() {
		r := byID[step.ID()]
		d.Steps = append(d.Steps, admin.AccountStepRow{
			ID: step.ID(), Title: step.Title("en"), Status: r.Status.String(), CompletedAt: admin.FormatTime(r.CompletedAt),
		})
	}
	pays, err := a.svc.Store().PaymentsByAccount(ctx, id, 50)
	if err != nil {
		return admin.AccountDetail{}, err
	}
	for _, p := range pays {
		d.Payments = append(d.Payments, admin.PaymentRow{
			ID: p.ID, Provider: p.Provider, ExternalID: p.ExternalID, Plan: p.PlanID, Status: p.Status.String(),
			Amount: p.Amount, Currency: p.Currency, PeriodDays: p.PeriodDays, CreatedAt: admin.FormatTime(p.CreatedAt),
			CreditedAt: admin.FormatTime(p.CreditedAt), RevokedAt: admin.FormatTime(p.RevokedAt),
		})
	}
	return d, nil
}

func (a accountAdmin) SetDisabled(ctx context.Context, id uint64, disabled bool) error {
	return notFound(a.svc.SetDisabled(ctx, id, disabled))
}

func (a accountAdmin) AdjustAccess(ctx context.Context, id uint64, days int) error {
	return notFound(a.svc.AdjustAccess(ctx, id, days))
}

func (a accountAdmin) SkipStep(ctx context.Context, id uint64, stepID string) error {
	return notFound(a.svc.SkipStep(ctx, id, stepID))
}

func accountRow(acct storage.Account) admin.AccountRow {
	return admin.AccountRow{
		ID: acct.ID, Username: acct.Username, Email: acct.Email, State: acct.State.String(),
		AccessUntil: admin.FormatTime(acct.AccessUntil), CreatedAt: admin.FormatTime(acct.CreatedAt),
	}
}

// notFound maps the store's not-found onto the dashboard's.
func notFound(err error) error {
	if errors.Is(err, storage.ErrAccountNotFound) {
		return admin.ErrAccountNotFound
	}
	return err
}
