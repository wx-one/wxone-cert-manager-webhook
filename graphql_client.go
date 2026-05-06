package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type gqlReq struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type gqlResp struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type projectItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *wxOneClient) GetDefaultProject(ctx context.Context) (projectItem, error) {
	q := `
query DefaultProject {
  getDefaultProject {
    code
    err
    msg { id }
  }
}`

	var out struct {
		DefaultProject struct {
			Code int        `json:"code"`
			Err  *string    `json:"err"`
			Msg  projectItem `json:"msg"`
		} `json:"getDefaultProject"`
	}

	if err := c.gql(ctx, q, nil, &out); err != nil {
		return projectItem{}, err
	}
	if out.DefaultProject.Code != 200 {
		if out.DefaultProject.Err != nil {
			return projectItem{}, fmt.Errorf(*out.DefaultProject.Err)
		}
		return projectItem{}, fmt.Errorf("get default project failed: %d", out.DefaultProject.Code)
	}
	if out.DefaultProject.Msg.ID == "" {
		return projectItem{}, fmt.Errorf("no default project found")
	}
	return out.DefaultProject.Msg, nil
}

type domainZone struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
}

func (c *wxOneClient) GetDomainZones(ctx context.Context, projectID string) ([]domainZone, error) {
	q := `
query Zones($projectId: UUID!) {
  getDomainZones(projectId: $projectId) {
    code
    err
    msg { id domain }
  }
}`

	vars := map[string]any{
		"projectId": projectID,
	}

	var out struct {
		Zones struct {
			Code int          `json:"code"`
			Err  *string      `json:"err"`
			Msg  []domainZone `json:"msg"`
		} `json:"getDomainZones"`
	}

	if err := c.gql(ctx, q, vars, &out); err != nil {
		return nil, err
	}
	if out.Zones.Code != 200 {
		if out.Zones.Err != nil {
			return nil, fmt.Errorf(*out.Zones.Err)
		}
		return nil, fmt.Errorf("get zones failed: %d", out.Zones.Code)
	}
	return out.Zones.Msg, nil
}

type rrset struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

func (c *wxOneClient) gql(
	ctx context.Context,
	query string,
	vars map[string]any,
	out any,
) error {
	body, _ := json.Marshal(gqlReq{Query: query, Variables: vars})
	req, _ := http.NewRequestWithContext(
		ctx,
		"POST",
		c.host+"/graphql",
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", c.cookie)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("graphql http %d: %s",
			resp.StatusCode, string(rb))
	}

	var gr gqlResp
	if err := json.Unmarshal(rb, &gr); err != nil {
		return err
	}
	if len(gr.Errors) > 0 {
		return fmt.Errorf("graphql error: %s", gr.Errors[0].Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(gr.Data, out)
}

func (c *wxOneClient) EnsureTXT(
	ctx context.Context,
	projectID string,
	zoneID string,
	name string,
	ttl int,
	token string,
) error {
	rr, err := c.GetRRset(ctx, projectID, zoneID, name, "TXT")
	if err != nil {
		return err
	}

	values := []string{token}
	if rr != nil && len(rr.Records) > 0 {
		seen := map[string]bool{}
		for _, v := range rr.Records {
			seen[v] = true
		}
		if !seen[token] {
			values = append(rr.Records, token)
		} else {
			values = rr.Records
		}
		ttl = rr.TTL
	}

	return c.UpsertTXT(ctx, projectID, zoneID, name, ttl, values)
}

func (c *wxOneClient) RemoveTXT(
	ctx context.Context,
	projectID string,
	zoneID string,
	name string,
	token string,
) error {
	rr, err := c.GetRRset(ctx, projectID, zoneID, name, "TXT")
	if err != nil {
		return err
	}
	if rr == nil || len(rr.Records) == 0 {
		return nil
	}

	remain := make([]string, 0, len(rr.Records))
	for _, v := range rr.Records {
		if v != token {
			remain = append(remain, v)
		}
	}

	if len(remain) == 0 {
		return c.DeleteRRset(ctx, projectID, zoneID, name, "TXT", rr.Records)
	}
	return c.UpsertTXT(ctx, projectID, zoneID, name, rr.TTL, remain)
}

func (c *wxOneClient) UpsertTXT(
	ctx context.Context,
	projectID string,
	zoneID string,
	name string,
	ttl int,
	values []string,
) error {
	q := `
mutation Upsert(
  $projectId: UUID!,
  $zoneId: UUID!,
  $name: String!,
  $ttl: Int,
  $records: [String!]!
) {
  upsertDomainZoneRRset(
    projectId: $projectId,
    zoneId: $zoneId,
    name: $name,
    type: TXT,
    ttl: $ttl,
    records: $records
  ) {
    code
    err
  }
}`

	vars := map[string]any{
		"projectId": projectID,
		"zoneId":    zoneID,
		"name":      name,
		"ttl":       ttl,
		"records":   values,
	}

	var out struct {
		Upsert struct {
			Code int     `json:"code"`
			Err  *string `json:"err"`
		} `json:"upsertDomainZoneRRset"`
	}

	if err := c.gql(ctx, q, vars, &out); err != nil {
		return err
	}
	if out.Upsert.Code != 200 {
		if out.Upsert.Err != nil {
			return fmt.Errorf(*out.Upsert.Err)
		}
		return fmt.Errorf("upsert failed: %d", out.Upsert.Code)
	}
	return nil
}

func (c *wxOneClient) DeleteRRset(
	ctx context.Context,
	projectID string,
	zoneID string,
	name string,
	typeVal string,
	records []string,
) error {
	q := `
mutation Del(
  $projectId: UUID!,
  $zoneId: UUID!,
  $name: String!,
  $type: DnsRecordType!,
  $records: [String!]!
) {
  deleteDomainZoneRRset(
    projectId: $projectId,
    zoneId: $zoneId,
    name: $name,
    type: $type,
    records: $records
  ) {
    code
    err
  }
}`

	vars := map[string]any{
		"projectId": projectID,
		"zoneId":    zoneID,
		"name":      name,
		"type":      typeVal,
		"records":   records,
	}

	var out struct {
		Del struct {
			Code int     `json:"code"`
			Err  *string `json:"err"`
		} `json:"deleteDomainZoneRRset"`
	}

	if err := c.gql(ctx, q, vars, &out); err != nil {
		return err
	}
	if out.Del.Code != 200 {
		if out.Del.Err != nil {
			return fmt.Errorf(*out.Del.Err)
		}
		return fmt.Errorf("delete failed: %d", out.Del.Code)
	}
	return nil
}

func (c *wxOneClient) GetRRset(
	ctx context.Context,
	projectID string,
	zoneID string,
	name string,
	typeVal string,
) (*rrset, error) {
	q := `
query Recs($projectId: UUID!, $zoneId: UUID!) {
  getDomainZoneRecords(projectId: $projectId, zoneId: $zoneId) {
    code
    err
    msg { name type ttl records }
  }
}`

	vars := map[string]any{
		"projectId": projectID,
		"zoneId":    zoneID,
	}

	var out struct {
		Recs struct {
			Code int     `json:"code"`
			Err  *string `json:"err"`
			Msg  []rrset `json:"msg"`
		} `json:"getDomainZoneRecords"`
	}

	if err := c.gql(ctx, q, vars, &out); err != nil {
		return nil, err
	}
	if out.Recs.Code != 200 {
		if out.Recs.Err != nil {
			return nil, fmt.Errorf(*out.Recs.Err)
		}
		return nil, fmt.Errorf("get records failed: %d", out.Recs.Code)
	}

	for _, r := range out.Recs.Msg {
		if r.Name == name && strings.EqualFold(r.Type, typeVal) {
			return &r, nil
		}
	}
	return nil, nil
}
