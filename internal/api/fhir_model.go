package api

// FHIR US Core Models - Following US Core Implementation Guide
// Reference: https://www.hl7.org/fhir/us/core/

// Common FHIR Data Types
type FHIRCoding struct {
	System  string `json:"system,omitempty"`
	Code    string `json:"code,omitempty"`
	Display string `json:"display,omitempty"`
}

type FHIRCodeableConcept struct {
	Coding []FHIRCoding `json:"coding,omitempty"`
	Text   string       `json:"text,omitempty"`
}

type FHIRReference struct {
	Reference string `json:"reference,omitempty"`
	Display   string `json:"display,omitempty"`
}

type FHIRPeriod struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type FHIRIdentifier struct {
	Use    string              `json:"use,omitempty"`
	Type   FHIRCodeableConcept `json:"type,omitempty"`
	System string              `json:"system,omitempty"`
	Value  string              `json:"value,omitempty"`
}

type FHIRHumanName struct {
	Use    string   `json:"use,omitempty"`
	Family string   `json:"family,omitempty"`
	Given  []string `json:"given,omitempty"`
	Prefix []string `json:"prefix,omitempty"`
	Suffix []string `json:"suffix,omitempty"`
}

type FHIRAddress struct {
	Use        string   `json:"use,omitempty"`
	Type       string   `json:"type,omitempty"`
	Line       []string `json:"line,omitempty"`
	City       string   `json:"city,omitempty"`
	State      string   `json:"state,omitempty"`
	PostalCode string   `json:"postalCode,omitempty"`
	Country    string   `json:"country,omitempty"`
}

type FHIRContactPoint struct {
	System string `json:"system,omitempty"`
	Value  string `json:"value,omitempty"`
	Use    string `json:"use,omitempty"`
	Rank   int    `json:"rank,omitempty"`
}

type FHIRQuantity struct {
	Value      float64 `json:"value,omitempty"`
	Unit       string  `json:"unit,omitempty"`
	System     string  `json:"system,omitempty"`
	Code       string  `json:"code,omitempty"`
	Comparator string  `json:"comparator,omitempty"`
}

type FHIRRange struct {
	Low  FHIRQuantity `json:"low,omitempty"`
	High FHIRQuantity `json:"high,omitempty"`
}

// US Core Patient Profile
type FHIRPatient struct {
	ResourceType  string              `json:"resourceType"`
	ID            string              `json:"id,omitempty"`
	Meta          FHIRMeta            `json:"meta,omitempty"`
	Identifier    []FHIRIdentifier    `json:"identifier,omitempty"`
	Active        bool                `json:"active,omitempty"`
	Name          []FHIRHumanName     `json:"name,omitempty"`
	Telecom       []FHIRContactPoint  `json:"telecom,omitempty"`
	Gender        string              `json:"gender,omitempty"`
	BirthDate     string              `json:"birthDate,omitempty"`
	Address       []FHIRAddress       `json:"address,omitempty"`
	Communication []FHIRCommunication `json:"communication,omitempty"`
}

type FHIRMeta struct {
	VersionId string   `json:"versionId,omitempty"`
	Profile   []string `json:"profile,omitempty"`
}

type FHIRCommunication struct {
	Language FHIRCodeableConcept `json:"language"`
}

// US Core Observation Profile
type FHIRObservation struct {
	ResourceType         string                     `json:"resourceType"`
	ID                   string                     `json:"id,omitempty"`
	Meta                 FHIRMeta                   `json:"meta,omitempty"`
	Status               string                     `json:"status"`
	Category             []FHIRCodeableConcept      `json:"category"`
	Code                 FHIRCodeableConcept        `json:"code"`
	Subject              FHIRReference              `json:"subject"`
	Encounter            FHIRReference              `json:"encounter,omitempty"`
	EffectiveDateTime    string                     `json:"effectiveDateTime,omitempty"`
	EffectivePeriod      FHIRPeriod                 `json:"effectivePeriod,omitempty"`
	Issued               string                     `json:"issued,omitempty"`
	Performer            []FHIRReference            `json:"performer,omitempty"`
	ValueQuantity        FHIRQuantity               `json:"valueQuantity,omitempty"`
	ValueCodeableConcept FHIRCodeableConcept        `json:"valueCodeableConcept,omitempty"`
	ValueString          string                     `json:"valueString,omitempty"`
	ValueBoolean         bool                       `json:"valueBoolean,omitempty"`
	ValueRange           FHIRRange                  `json:"valueRange,omitempty"`
	Component            []FHIRObservationComponent `json:"component,omitempty"`
}

type FHIRObservationComponent struct {
	Code                 FHIRCodeableConcept `json:"code"`
	ValueQuantity        FHIRQuantity        `json:"valueQuantity,omitempty"`
	ValueCodeableConcept FHIRCodeableConcept `json:"valueCodeableConcept,omitempty"`
	ValueString          string              `json:"valueString,omitempty"`
}

// US Core Encounter Profile
type FHIREncounter struct {
	ResourceType string                `json:"resourceType"`
	ID           string                `json:"id,omitempty"`
	Meta         FHIRMeta              `json:"meta,omitempty"`
	Status       string                `json:"status"`
	Class        FHIRCoding            `json:"class"`
	Type         []FHIRCodeableConcept `json:"type,omitempty"`
	Subject      FHIRReference         `json:"subject"`
	Participant  []FHIRParticipant     `json:"participant,omitempty"`
	Period       FHIRPeriod            `json:"period,omitempty"`
	ReasonCode   []FHIRCodeableConcept `json:"reasonCode,omitempty"`
	Location     []FHIRLocation        `json:"location,omitempty"`
}

type FHIRParticipant struct {
	Type       []FHIRCodeableConcept `json:"type,omitempty"`
	Individual FHIRReference         `json:"individual,omitempty"`
}

type FHIRLocation struct {
	Location FHIRReference `json:"location"`
}

// US Core Condition Profile
type FHIRCondition struct {
	ResourceType       string                `json:"resourceType"`
	ID                 string                `json:"id,omitempty"`
	Meta               FHIRMeta              `json:"meta,omitempty"`
	ClinicalStatus     FHIRCodeableConcept   `json:"clinicalStatus"`
	VerificationStatus FHIRCodeableConcept   `json:"verificationStatus"`
	Category           []FHIRCodeableConcept `json:"category,omitempty"`
	Code               FHIRCodeableConcept   `json:"code"`
	Subject            FHIRReference         `json:"subject"`
	Encounter          FHIRReference         `json:"encounter,omitempty"`
	OnsetDateTime      string                `json:"onsetDateTime,omitempty"`
	OnsetPeriod        FHIRPeriod            `json:"onsetPeriod,omitempty"`
}

// US Core Medication Profile
type FHIRMedication struct {
	ResourceType string              `json:"resourceType"`
	ID           string              `json:"id,omitempty"`
	Meta         FHIRMeta            `json:"meta,omitempty"`
	Code         FHIRCodeableConcept `json:"code,omitempty"`
	Form         FHIRCodeableConcept `json:"form,omitempty"`
}

// US Core MedicationRequest Profile
type FHIRMedicationRequest struct {
	ResourceType              string              `json:"resourceType"`
	ID                        string              `json:"id,omitempty"`
	Meta                      FHIRMeta            `json:"meta,omitempty"`
	Status                    string              `json:"status"`
	Intent                    string              `json:"intent"`
	MedicationReference       FHIRReference       `json:"medicationReference,omitempty"`
	MedicationCodeableConcept FHIRCodeableConcept `json:"medicationCodeableConcept,omitempty"`
	Subject                   FHIRReference       `json:"subject"`
	Encounter                 FHIRReference       `json:"encounter,omitempty"`
	AuthoredOn                string              `json:"authoredOn,omitempty"`
	Requester                 FHIRReference       `json:"requester,omitempty"`
	DosageInstruction         []FHIRDosage        `json:"dosageInstruction,omitempty"`
}

type FHIRDosage struct {
	Text   string              `json:"text,omitempty"`
	Timing FHIRTiming          `json:"timing,omitempty"`
	Route  FHIRCodeableConcept `json:"route,omitempty"`
}

type FHIRTiming struct {
	Repeat FHIRRepeat `json:"repeat,omitempty"`
}

type FHIRRepeat struct {
	Frequency  int    `json:"frequency,omitempty"`
	Period     int    `json:"period,omitempty"`
	PeriodUnit string `json:"periodUnit,omitempty"`
}

// US Core Procedure Profile
type FHIRProcedure struct {
	ResourceType      string                   `json:"resourceType"`
	ID                string                   `json:"id,omitempty"`
	Meta              FHIRMeta                 `json:"meta,omitempty"`
	Status            string                   `json:"status"`
	Code              FHIRCodeableConcept      `json:"code"`
	Subject           FHIRReference            `json:"subject"`
	Encounter         FHIRReference            `json:"encounter,omitempty"`
	PerformedDateTime string                   `json:"performedDateTime,omitempty"`
	PerformedPeriod   FHIRPeriod               `json:"performedPeriod,omitempty"`
	Performer         []FHIRProcedurePerformer `json:"performer,omitempty"`
}

type FHIRProcedurePerformer struct {
	Actor FHIRReference `json:"actor"`
}

// US Core DiagnosticReport Profile
type FHIRDiagnosticReport struct {
	ResourceType      string                `json:"resourceType"`
	ID                string                `json:"id,omitempty"`
	Meta              FHIRMeta              `json:"meta,omitempty"`
	Status            string                `json:"status"`
	Category          []FHIRCodeableConcept `json:"category"`
	Code              FHIRCodeableConcept   `json:"code"`
	Subject           FHIRReference         `json:"subject"`
	Encounter         FHIRReference         `json:"encounter,omitempty"`
	EffectiveDateTime string                `json:"effectiveDateTime,omitempty"`
	Issued            string                `json:"issued,omitempty"`
	Performer         []FHIRReference       `json:"performer,omitempty"`
	Result            []FHIRReference       `json:"result,omitempty"`
}

// US Core Practitioner Profile
type FHIRPractitioner struct {
	ResourceType  string              `json:"resourceType"`
	ID            string              `json:"id,omitempty"`
	Meta          FHIRMeta            `json:"meta,omitempty"`
	Identifier    []FHIRIdentifier    `json:"identifier,omitempty"`
	Active        bool                `json:"active,omitempty"`
	Name          []FHIRHumanName     `json:"name,omitempty"`
	Telecom       []FHIRContactPoint  `json:"telecom,omitempty"`
	Address       []FHIRAddress       `json:"address,omitempty"`
	Gender        string              `json:"gender,omitempty"`
	Qualification []FHIRQualification `json:"qualification,omitempty"`
}

type FHIRQualification struct {
	Code   FHIRCodeableConcept `json:"code"`
	Period FHIRPeriod          `json:"period,omitempty"`
}

// US Core Organization Profile
type FHIROrganization struct {
	ResourceType string             `json:"resourceType"`
	ID           string             `json:"id,omitempty"`
	Meta         FHIRMeta           `json:"meta,omitempty"`
	Identifier   []FHIRIdentifier   `json:"identifier,omitempty"`
	Active       bool               `json:"active,omitempty"`
	Name         string             `json:"name,omitempty"`
	Telecom      []FHIRContactPoint `json:"telecom,omitempty"`
	Address      []FHIRAddress      `json:"address,omitempty"`
}

// FHIR Bundle for search results
type FHIRBundle struct {
	ResourceType string      `json:"resourceType"`
	ID           string      `json:"id,omitempty"`
	Type         string      `json:"type"`
	Total        int         `json:"total,omitempty"`
	Entry        []FHIREntry `json:"entry,omitempty"`
}

type FHIREntry struct {
	FullUrl  string      `json:"fullUrl,omitempty"`
	Resource interface{} `json:"resource"`
}

// FHIR OperationOutcome for errors
type FHIROperationOutcome struct {
	ResourceType string      `json:"resourceType"`
	Issue        []FHIRIssue `json:"issue"`
}

type FHIRIssue struct {
	Severity    string              `json:"severity"`
	Code        string              `json:"code"`
	Diagnostics string              `json:"diagnostics,omitempty"`
	Details     FHIRCodeableConcept `json:"details,omitempty"`
}
