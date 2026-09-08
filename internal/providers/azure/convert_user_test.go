package azure

import (
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

// USER_NO_MANAGER: GetUsers never requested the "manager" navigation
// property (not $select-able, needs $expand) and convertAzureUser never
// read it, so user.Manager stayed "" for 100% of Azure-sourced accounts.

func TestConvertAzureUser_Manager(t *testing.T) {
	t.Run("manager expanded as full user -> UPN captured", func(t *testing.T) {
		mgr := models.NewUser()
		mgrID := "mgr-id-1"
		mgrUPN := "boss@example.com"
		mgr.SetId(&mgrID)
		mgr.SetUserPrincipalName(&mgrUPN)

		u := models.NewUser()
		u.SetManager(mgr)

		got := convertAzureUser(u)
		if got.Manager != mgrUPN {
			t.Fatalf("Manager = %q, want %q", got.Manager, mgrUPN)
		}
	})

	t.Run("manager expanded as bare directory object -> id fallback", func(t *testing.T) {
		mgr := models.NewDirectoryObject()
		mgrID := "mgr-id-2"
		mgr.SetId(&mgrID)

		u := models.NewUser()
		u.SetManager(mgr)

		got := convertAzureUser(u)
		if got.Manager != mgrID {
			t.Fatalf("Manager = %q, want %q", got.Manager, mgrID)
		}
	})

	t.Run("no manager -> field stays empty", func(t *testing.T) {
		u := models.NewUser()
		got := convertAzureUser(u)
		if got.Manager != "" {
			t.Fatalf("Manager = %q, want empty", got.Manager)
		}
	})
}
