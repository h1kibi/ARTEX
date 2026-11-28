package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A URL whose authority is an IP literal must land in assets.ip (not domain) and
// must NOT produce a fake root_domain row — otherwise coverage's net predicate
// never matches and internal IP services are invisible (docs §4.5).
func TestBareIPURLStoredAsIPAsset(t *testing.T) {
	d, av2, _ := testSetup(t)
	defer d.Close()

	stamp := time.Now().UnixNano()
	// Unique address inside a /24 we scope below.
	ip := fmt.Sprintf("10.%d.%d.%d", (stamp>>16)&0x7f, (stamp>>8)&0xff, stamp&0xfe)
	url := fmt.Sprintf("http://%s:8080/api", ip)

	id, err := av2.UpsertHTTPService(UpsertHTTPServiceReq{URL: url})
	if err != nil {
		t.Fatalf("upsert http service: %v", err)
	}
	t.Cleanup(func() { deleteAsset(d, id) })
	var domain, rootDomain, storedIP, cseg *string
	if err := d.QueryRow(`SELECT domain, root_domain, ip, c_segment::text FROM assets WHERE id=$1`, id).
		Scan(&domain, &rootDomain, &storedIP, &cseg); err != nil {
		t.Fatal(err)
	}
	if storedIP == nil || *storedIP != ip {
		t.Fatalf("ip column=%v want %s (domain=%v)", storedIP, ip, domain)
	}
	if domain != nil && *domain != "" {
		t.Fatalf("IP literal leaked into domain column: %q", *domain)
	}
	if rootDomain != nil && *rootDomain != "" {
		t.Fatalf("IP literal leaked into root_domain column: %q", *rootDomain)
	}
	if cseg == nil || *cseg == "" {
		t.Fatalf("c_segment not derived from the IP literal")
	}

	// No bogus root_domain asset for the address.
	var bogus int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='root_domain' AND domain=$1`, ip).Scan(&bogus); err != nil {
		t.Fatal(err)
	}
	if bogus != 0 {
		t.Fatalf("linkHostAssets created %d fake root_domain row(s) for %s", bogus, ip)
	}

	// Endpoint with an IP-literal host behaves identically.
	eid, err := av2.UpsertEndpoint(UpsertEndpointReq{URL: fmt.Sprintf("http://%s:8080/x?q=1", ip), Method: "GET"})
	if err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	t.Cleanup(func() { deleteAsset(d, eid) })
	var epIP, epDomain *string
	if err := d.QueryRow(`SELECT ip, domain FROM assets WHERE id=$1`, eid).Scan(&epIP, &epDomain); err != nil {
		t.Fatal(err)
	}
	if epIP == nil || *epIP != ip {
		t.Fatalf("endpoint ip=%v want %s", epIP, ip)
	}
	if epDomain != nil && *epDomain != "" {
		t.Fatalf("endpoint domain=%q want empty for an IP literal", *epDomain)
	}
}

// Coverage must count an internal IP service: an ip/cidr scope matches the ip
// column, and it also matches a legacy row that stored the address in `domain`
// (old databases), and a keyword scope matches by substring.
func TestCoverageMatchesIPAndKeywordScope(t *testing.T) {
	d, av2, _ := testSetup(t)
	defer d.Close()

	task, err := d.CreateTask("coverage ip scope", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	stamp := time.Now().UnixNano()
	net := fmt.Sprintf("10.%d.%d.0/24", (stamp>>16)&0x7f, (stamp>>8)&0xff)
	ip := fmt.Sprintf("10.%d.%d.7", (stamp>>16)&0x7f, (stamp>>8)&0xff)
	legacyIP := fmt.Sprintf("10.%d.%d.8", (stamp>>16)&0x7f, (stamp>>8)&0xff)
	keyword := fmt.Sprintf("intranet-portal-%d", stamp)

	// New-style asset (ip column filled) via the production path.
	id, err := av2.UpsertHTTPService(UpsertHTTPServiceReq{URL: fmt.Sprintf("http://%s:8080/", ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, id) })

	// Legacy-style asset: address in `domain`, ip column NULL, plus a keyword hit.
	var legacyID, keywordID int64
	if err := d.QueryRow(`INSERT INTO assets(type,url,domain,service_type,service_name,port,task_ids,last_seen)
VALUES ('service',$1,$2,'http','http',8080,ARRAY[]::bigint[],now()) RETURNING id`,
		"http://"+legacyIP+":8080/", legacyIP).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, legacyID) })
	if err := d.QueryRow(`INSERT INTO assets(type,url,domain,service_type,service_name,port,task_ids,last_seen)
VALUES ('service',$1,$2,'http','http',9090,ARRAY[]::bigint[],now()) RETURNING id`,
		"http://host-"+keyword+".invalid:9090/", "host-"+keyword+".invalid").Scan(&keywordID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, keywordID) })

	// Scope: the /24 covers both IP forms; the keyword covers the third asset.
	if err := av2.upsertTaskScope(TaskScope{TaskID: task.ID, Kind: "cidr", Net: net}); err != nil {
		t.Fatal(err)
	}
	if err := av2.upsertTaskScope(TaskScope{TaskID: task.ID, Kind: "keyword", Value: keyword}); err != nil {
		t.Fatal(err)
	}

	cov, err := av2.TaskCoverage(task.ID, task.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Denominator < 3 {
		t.Fatalf("coverage denominator=%d want >=3 (ip asset + legacy IP-literal domain + keyword hit); by_type=%+v", cov.Denominator, cov.ByType)
	}

	untested, total, err := av2.ListUntestedAssetsWithSources(task.ID, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[int64]bool{}
	for _, a := range untested {
		found[a.ID] = true
	}
	for _, want := range []int64{id, legacyID, keywordID} {
		if !found[want] {
			t.Fatalf("asset %d missing from untested backlog (total=%d list=%v)", want, total, untested)
		}
	}

	// HostsByTaskWithSources must surface all three hosts too.
	hosts, err := av2.HostsByTaskWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	hostSet := map[string]bool{}
	for _, h := range hosts {
		hostSet[h] = true
	}
	for _, want := range []string{ip, legacyIP, "host-" + keyword + ".invalid"} {
		if !hostSet[want] {
			t.Fatalf("host %s missing from HostsByTaskWithSources: %v", want, hosts)
		}
	}
}

// AddAutoScope must scope an IP-literal service by address even when the caller
// never filled the ip field (a bare URL is the normal case).
func TestAddAutoScopeUsesURLIPLiteral(t *testing.T) {
	_, av2, _ := testSetup(t)
	// No DB mutation needed beyond the scope insert; use a throwaway task id that
	// satisfies the FK.
	d := av2.db
	task, err := d.CreateTask("auto scope ip", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	if err := av2.AddAutoScope(task.ID, "service", "", "http://10.42.7.9:8443/app", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := av2.ListTaskScope(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Kind != "ip" || rows[0].Net != "10.42.7.9/32" {
		t.Fatalf("auto scope=%+v want ip 10.42.7.9/32", rows)
	}
}

// When the URL host is an IP literal it is the authoritative address: a caller's
// conflicting req.IP must not win, or the row (domain empty) would point at a
// different address than AddAutoScope scoped.
func TestBareIPHostOverridesConflictingReqIP(t *testing.T) {
	d, av2, _ := testSetup(t)
	defer d.Close()

	stamp := time.Now().UnixNano()
	hostIP := fmt.Sprintf("10.%d.%d.9", (stamp>>16)&0x7f, (stamp>>8)&0xff)
	otherIP := fmt.Sprintf("10.%d.%d.77", (stamp>>16)&0x7f, (stamp>>8)&0xff)

	id, err := av2.UpsertHTTPService(UpsertHTTPServiceReq{
		URL: fmt.Sprintf("http://%s:8080/", hostIP),
		IP:  otherIP, // stale DNS answer / caller mistake
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, id) })
	var storedIP, cseg *string
	if err := d.QueryRow(`SELECT ip, c_segment::text FROM assets WHERE id=$1`, id).Scan(&storedIP, &cseg); err != nil {
		t.Fatal(err)
	}
	if storedIP == nil || *storedIP != hostIP {
		t.Fatalf("ip=%v want the URL host %s (conflicting req.IP won)", storedIP, hostIP)
	}
	if cseg == nil || !strings.HasPrefix(*cseg, hostIP[:strings.LastIndex(hostIP, ".")]+".0/") {
		t.Fatalf("c_segment=%v does not derive from the URL host %s", cseg, hostIP)
	}

	// Endpoint behaves identically.
	eid, err := av2.UpsertEndpoint(UpsertEndpointReq{
		URL: fmt.Sprintf("http://%s:8080/e", hostIP), Method: "GET", IP: otherIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, eid) })
	var epIP *string
	if err := d.QueryRow(`SELECT ip FROM assets WHERE id=$1`, eid).Scan(&epIP); err != nil {
		t.Fatal(err)
	}
	if epIP == nil || *epIP != hostIP {
		t.Fatalf("endpoint ip=%v want %s", epIP, hostIP)
	}

	// Other service: the bare-IP domain is authoritative too.
	oid, err := av2.UpsertOtherService(UpsertOtherServiceReq{
		Domain: hostIP, IP: otherIP, Port: 9999, ServiceName: "custom",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteAsset(d, oid) })
	var osIP, osDomain *string
	if err := d.QueryRow(`SELECT ip, domain FROM assets WHERE id=$1`, oid).Scan(&osIP, &osDomain); err != nil {
		t.Fatal(err)
	}
	if osIP == nil || *osIP != hostIP {
		t.Fatalf("other service ip=%v want %s", osIP, hostIP)
	}
	if osDomain != nil && *osDomain != "" {
		t.Fatalf("other service domain=%q want empty", *osDomain)
	}
}
