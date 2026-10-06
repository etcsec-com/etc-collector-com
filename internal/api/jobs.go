package api

import (
	"sync"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/google/uuid"
)

// JobStatus represents the status of a job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
)

// Job represents an async job
type Job struct {
	ID          string             `json:"id"`
	Type        string             `json:"type"`
	Status      JobStatus          `json:"status"`
	CreatedAt   time.Time          `json:"createdAt"`
	CompletedAt *time.Time         `json:"completedAt,omitempty"`
	Error       string             `json:"error,omitempty"`
	Result      *types.AuditResult `json:"result,omitempty"`
}

// JobStore manages async jobs
type JobStore struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

// NewJobStore creates a new job store
func NewJobStore() *JobStore {
	return &JobStore{
		jobs: make(map[string]*Job),
	}
}

// Create creates a new job
func (s *JobStore) Create(jobType string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()

	job := &Job{
		ID:        uuid.New().String(),
		Type:      jobType,
		Status:    JobStatusRunning,
		CreatedAt: time.Now(),
	}

	s.jobs[job.ID] = job
	return job
}

// Get retrieves a job by ID
func (s *JobStore) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.jobs[id]
	return job, ok
}

// List returns all jobs
func (s *JobStore) List() []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]*Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	return jobs
}

// Complete marks a job as completed
func (s *JobStore) Complete(id string, result *types.AuditResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if job, ok := s.jobs[id]; ok {
		now := time.Now()
		job.Status = JobStatusCompleted
		job.CompletedAt = &now
		job.Result = result
	}
}

// Fail marks a job as failed
func (s *JobStore) Fail(id string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if job, ok := s.jobs[id]; ok {
		now := time.Now()
		job.Status = JobStatusFailed
		job.CompletedAt = &now
		job.Error = err.Error()
	}
}

// Cleanup removes old completed/failed jobs
func (s *JobStore) Cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, job := range s.jobs {
		if job.CompletedAt != nil && job.CompletedAt.Before(cutoff) {
			delete(s.jobs, id)
		}
	}
}
