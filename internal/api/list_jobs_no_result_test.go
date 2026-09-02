package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/gin-gonic/gin"
)

// TestListJobsHandler_OmitsResult — T_138 defect 2. qa found, replaying the
// same jobId against both routes right after a POST /audit/ad?async=true
// (T_137, docs/rejeu-doc/qa/BILAN.md A#17): GET /api/v1/audit/jobs returned a
// FLAT result object (types.AuditResult's own JSON tags — timestamp,
// duration, score, provider, domain, findings, ...) while GET
// /api/v1/audit/jobs/:id returned the ENVELOPED {success,provider,audit}
// shape for the identical job, via types.ConvertToTSFormat. Two schemas for
// one jobId. The lead verified the embedded GUI's loadJobs() (app.js) never
// reads result from the list — only openAudit()'s getJob(id) does — so the
// list dropping result entirely (qa's proposal) is the safe fix: this test
// locks that the list response carries no "result" key at all, regardless of
// job status.
func TestListJobsHandler_OmitsResult(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := NewServer(config.Default(), providers.NewManager())
	s.SetVersionInfo("3.1.39", "pro")

	job := s.jobStore.Create("ad_audit")
	s.jobStore.Complete(job.ID, &types.AuditResult{
		Score: 42,
	})

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit/jobs", nil)
	s.listJobsHandler(c)

	var body struct {
		Jobs []map[string]interface{} `json:"jobs"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(body.Jobs))
	}

	if _, present := body.Jobs[0]["result"]; present {
		t.Fatalf(`jobs[0] still carries "result": %v — the list must not renvoie result at all (defect 2's flat shape diverges from getJobHandler's enveloped shape for the same jobId)`, body.Jobs[0]["result"])
	}
	if body.Jobs[0]["id"] != job.ID {
		t.Fatalf("jobs[0][\"id\"] = %v, want %q — the summary must still carry the fields the GUI's loadJobs()/sort actually use", body.Jobs[0]["id"], job.ID)
	}
	if body.Jobs[0]["status"] != string(job.Status) {
		t.Fatalf("jobs[0][\"status\"] = %v, want %q", body.Jobs[0]["status"], job.Status)
	}
}
