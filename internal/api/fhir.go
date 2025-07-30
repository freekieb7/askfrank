package api

import "github.com/gofiber/fiber/v2"

// US Core FHIR Endpoint Stubs
// Reference: https://www.hl7.org/fhir/us/core/

type FHIRHandler struct {
}

// Patient
func (h *FHIRHandler) FHIRPatientRead(c *fiber.Ctx) error {
	// GET /Patient/:id
	return c.JSON(fiber.Map{"resourceType": "Patient"})
}

func (h *FHIRHandler) FHIRPatientSearch(c *fiber.Ctx) error {
	// GET /Patient?name=...&birthdate=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Observation
func (h *FHIRHandler) FHIRObservationRead(c *fiber.Ctx) error {
	// GET /Observation/:id
	return c.JSON(fiber.Map{"resourceType": "Observation"})
}

func (h *FHIRHandler) FHIRObservationSearch(c *fiber.Ctx) error {
	// GET /Observation?patient=...&category=...&code=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Encounter
func (h *FHIRHandler) FHIREncounterRead(c *fiber.Ctx) error {
	// GET /Encounter/:id
	return c.JSON(fiber.Map{"resourceType": "Encounter"})
}

func (h *FHIRHandler) FHIREncounterSearch(c *fiber.Ctx) error {
	// GET /Encounter?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Condition
func (h *FHIRHandler) FHIRConditionRead(c *fiber.Ctx) error {
	// GET /Condition/:id
	return c.JSON(fiber.Map{"resourceType": "Condition"})
}

func (h *FHIRHandler) FHIRConditionSearch(c *fiber.Ctx) error {
	// GET /Condition?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Medication
func (h *FHIRHandler) FHIRMedicationRead(c *fiber.Ctx) error {
	// GET /Medication/:id
	return c.JSON(fiber.Map{"resourceType": "Medication"})
}

func (h *FHIRHandler) FHIRMedicationSearch(c *fiber.Ctx) error {
	// GET /Medication?code=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// MedicationRequest
func (h *FHIRHandler) FHIRMedicationRequestRead(c *fiber.Ctx) error {
	// GET /MedicationRequest/:id
	return c.JSON(fiber.Map{"resourceType": "MedicationRequest"})
}

func (h *FHIRHandler) FHIRMedicationRequestSearch(c *fiber.Ctx) error {
	// GET /MedicationRequest?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Procedure
func (h *FHIRHandler) FHIRProcedureRead(c *fiber.Ctx) error {
	// GET /Procedure/:id
	return c.JSON(fiber.Map{"resourceType": "Procedure"})
}

func (h *FHIRHandler) FHIRProcedureSearch(c *fiber.Ctx) error {
	// GET /Procedure?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// DiagnosticReport
func (h *FHIRHandler) FHIRDiagnosticReportRead(c *fiber.Ctx) error {
	// GET /DiagnosticReport/:id
	return c.JSON(fiber.Map{"resourceType": "DiagnosticReport"})
}

func (h *FHIRHandler) FHIRDiagnosticReportSearch(c *fiber.Ctx) error {
	// GET /DiagnosticReport?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Practitioner
func (h *FHIRHandler) FHIRPractitionerRead(c *fiber.Ctx) error {
	// GET /Practitioner/:id
	return c.JSON(fiber.Map{"resourceType": "Practitioner"})
}

func (h *FHIRHandler) FHIRPractitionerSearch(c *fiber.Ctx) error {
	// GET /Practitioner?name=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Organization
func (h *FHIRHandler) FHIROrganizationRead(c *fiber.Ctx) error {
	// GET /Organization/:id
	return c.JSON(fiber.Map{"resourceType": "Organization"})
}

func (h *FHIRHandler) FHIROrganizationSearch(c *fiber.Ctx) error {
	// GET /Organization?name=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// AllergyIntolerance
func (h *FHIRHandler) FHIRAllergyIntoleranceRead(c *fiber.Ctx) error {
	// GET /AllergyIntolerance/:id
	return c.JSON(fiber.Map{"resourceType": "AllergyIntolerance"})
}

func (h *FHIRHandler) FHIRAllergyIntoleranceSearch(c *fiber.Ctx) error {
	// GET /AllergyIntolerance?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// CarePlan
func (h *FHIRHandler) FHIRCarePlanRead(c *fiber.Ctx) error {
	// GET /CarePlan/:id
	return c.JSON(fiber.Map{"resourceType": "CarePlan"})
}

func (h *FHIRHandler) FHIRCarePlanSearch(c *fiber.Ctx) error {
	// GET /CarePlan?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// CareTeam
func (h *FHIRHandler) FHIRCareTeamRead(c *fiber.Ctx) error {
	// GET /CareTeam/:id
	return c.JSON(fiber.Map{"resourceType": "CareTeam"})
}

func (h *FHIRHandler) FHIRCareTeamSearch(c *fiber.Ctx) error {
	// GET /CareTeam?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Goal
func (h *FHIRHandler) FHIRGoalRead(c *fiber.Ctx) error {
	// GET /Goal/:id
	return c.JSON(fiber.Map{"resourceType": "Goal"})
}

func (h *FHIRHandler) FHIRGoalSearch(c *fiber.Ctx) error {
	// GET /Goal?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Immunization
func (h *FHIRHandler) FHIRImmunizationRead(c *fiber.Ctx) error {
	// GET /Immunization/:id
	return c.JSON(fiber.Map{"resourceType": "Immunization"})
}

func (h *FHIRHandler) FHIRImmunizationSearch(c *fiber.Ctx) error {
	// GET /Immunization?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// DocumentReference (additional US Core resource)
func (h *FHIRHandler) FHIRDocumentReferenceRead(c *fiber.Ctx) error {
	// GET /DocumentReference/:id
	return c.JSON(fiber.Map{"resourceType": "DocumentReference"})
}

func (h *FHIRHandler) FHIRDocumentReferenceSearch(c *fiber.Ctx) error {
	// GET /DocumentReference?patient=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}

// Location (additional US Core resource)
func (h *FHIRHandler) FHIRLocationRead(c *fiber.Ctx) error {
	// GET /Location/:id
	return c.JSON(fiber.Map{"resourceType": "Location"})
}

func (h *FHIRHandler) FHIRLocationSearch(c *fiber.Ctx) error {
	// GET /Location?name=...
	return c.JSON(fiber.Map{"resourceType": "Bundle", "type": "searchset", "entry": []interface{}{}})
}
