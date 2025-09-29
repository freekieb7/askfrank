package organisation

import (
	"fmt"
	"hp/internal/stripe"
)

type SubscriptionPlan string

const (
	SubscriptionPlanFree SubscriptionPlan = "Free"
	SubscriptionPlanPro  SubscriptionPlan = "Pro"
)

func (p SubscriptionPlan) IsValid() bool {
	switch p {
	case SubscriptionPlanFree, SubscriptionPlanPro:
		return true
	default:
		return false
	}
}

func (p SubscriptionPlan) String() string {
	return string(p)
}

func ParseSubscriptionPlan(s string) (SubscriptionPlan, error) {
	plan := SubscriptionPlan(s)
	if !plan.IsValid() {
		return "", fmt.Errorf("invalid subscription plan: %s", s)
	}
	return plan, nil
}

var (
	PlanToPriceID = map[SubscriptionPlan]stripe.PriceID{
		SubscriptionPlanFree: stripe.PriceIDFreePlan,
		SubscriptionPlanPro:  stripe.PriceIDProPlan,
	}
	PriceIDToPlan = map[stripe.PriceID]SubscriptionPlan{
		stripe.PriceIDFreePlan: SubscriptionPlanFree,
		stripe.PriceIDProPlan:  SubscriptionPlanPro,
	}
)
