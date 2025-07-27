package api

import "github.com/gofiber/fiber/v2"

// US Core FHIR Endpoint Stubs
// Reference: https://www.hl7.org/fhir/us/core/

// Patient
func (h *Handler) FHIRPatientRead(c *fiber.Ctx) error {
	// GET /Patient/:id
	return c.JSON(fiber.Map{"resourceType": "Patient"})
}

func (h *Handler) FHIRPatientSearch(c *fiber.Ctx) error {
	// GET /Patient?name=...&birthdate=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Observation
func (h *Handler) FHIRObservationRead(c *fiber.Ctx) error {
	// GET /Observation/:id
	return c.JSON(fiber.Map{"resourceType": "Observation"})
}

func (h *Handler) FHIRObservationSearch(c *fiber.Ctx) error {
	// GET /Observation?patient=...&category=...&code=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Encounter
func (h *Handler) FHIREncounterRead(c *fiber.Ctx) error {
	// GET /Encounter/:id
	return c.JSON(fiber.Map{"resourceType": "Encounter"})
}

func (h *Handler) FHIREncounterSearch(c *fiber.Ctx) error {
	// GET /Encounter?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Condition
func (h *Handler) FHIRConditionRead(c *fiber.Ctx) error {
	// GET /Condition/:id
	return c.JSON(fiber.Map{"resourceType": "Condition"})
}

func (h *Handler) FHIRConditionSearch(c *fiber.Ctx) error {
	// GET /Condition?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Medication
func (h *Handler) FHIRMedicationRead(c *fiber.Ctx) error {
	// GET /Medication/:id
	return c.JSON(fiber.Map{"resourceType": "Medication"})
}

func (h *Handler) FHIRMedicationSearch(c *fiber.Ctx) error {
	// GET /Medication?code=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// MedicationRequest
func (h *Handler) FHIRMedicationRequestRead(c *fiber.Ctx) error {
	// GET /MedicationRequest/:id
	return c.JSON(fiber.Map{"resourceType": "MedicationRequest"})
}

func (h *Handler) FHIRMedicationRequestSearch(c *fiber.Ctx) error {
	// GET /MedicationRequest?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Procedure
func (h *Handler) FHIRProcedureRead(c *fiber.Ctx) error {
	// GET /Procedure/:id
	return c.JSON(fiber.Map{"resourceType": "Procedure"})
}

func (h *Handler) FHIRProcedureSearch(c *fiber.Ctx) error {
	// GET /Procedure?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// DiagnosticReport
func (h *Handler) FHIRDiagnosticReportRead(c *fiber.Ctx) error {
	// GET /DiagnosticReport/:id
	return c.JSON(fiber.Map{"resourceType": "DiagnosticReport"})
}

func (h *Handler) FHIRDiagnosticReportSearch(c *fiber.Ctx) error {
	// GET /DiagnosticReport?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Practitioner
func (h *Handler) FHIRPractitionerRead(c *fiber.Ctx) error {
	// GET /Practitioner/:id
	return c.JSON(fiber.Map{"resourceType": "Practitioner"})
}

func (h *Handler) FHIRPractitionerSearch(c *fiber.Ctx) error {
	// GET /Practitioner?name=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Organization
func (h *Handler) FHIROrganizationRead(c *fiber.Ctx) error {
	// GET /Organization/:id
	return c.JSON(fiber.Map{"resourceType": "Organization"})
}

func (h *Handler) FHIROrganizationSearch(c *fiber.Ctx) error {
	// GET /Organization?name=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// AllergyIntolerance
func (h *Handler) FHIRAllergyIntoleranceRead(c *fiber.Ctx) error {
	// GET /AllergyIntolerance/:id
	return c.JSON(fiber.Map{"resourceType": "AllergyIntolerance"})
}

func (h *Handler) FHIRAllergyIntoleranceSearch(c *fiber.Ctx) error {
	// GET /AllergyIntolerance?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// CarePlan
func (h *Handler) FHIRCarePlanRead(c *fiber.Ctx) error {
	// GET /CarePlan/:id
	return c.JSON(fiber.Map{"resourceType": "CarePlan"})
}

func (h *Handler) FHIRCarePlanSearch(c *fiber.Ctx) error {
	// GET /CarePlan?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// CareTeam
func (h *Handler) FHIRCareTeamRead(c *fiber.Ctx) error {
	// GET /CareTeam/:id
	return c.JSON(fiber.Map{"resourceType": "CareTeam"})
}

func (h *Handler) FHIRCareTeamSearch(c *fiber.Ctx) error {
	// GET /CareTeam?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Goal
func (h *Handler) FHIRGoalRead(c *fiber.Ctx) error {
	// GET /Goal/:id
	return c.JSON(fiber.Map{"resourceType": "Goal"})
}

func (h *Handler) FHIRGoalSearch(c *fiber.Ctx) error {
	// GET /Goal?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Immunization
func (h *Handler) FHIRImmunizationRead(c *fiber.Ctx) error {
	// GET /Immunization/:id
	return c.JSON(fiber.Map{"resourceType": "Immunization"})
}

func (h *Handler) FHIRImmunizationSearch(c *fiber.Ctx) error {
	// GET /Immunization?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// DocumentReference (additional US Core resource)
func (h *Handler) FHIRDocumentReferenceRead(c *fiber.Ctx) error {
	// GET /DocumentReference/:id
	return c.JSON(fiber.Map{"resourceType": "DocumentReference"})
}

func (h *Handler) FHIRDocumentReferenceSearch(c *fiber.Ctx) error {
	// GET /DocumentReference?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Location (additional US Core resource)
func (h *Handler) FHIRLocationRead(c *fiber.Ctx) error {
	// GET /Location/:id
	return c.JSON(fiber.Map{"resourceType": "Location"})
}

func (h *Handler) FHIRLocationSearch(c *fiber.Ctx) error {
	// GET /Location?name=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}
