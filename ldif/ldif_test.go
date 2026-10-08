package ldif_test

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/go-directory/util/ldif"
)

var ldifRFC2849Example = `version: 1
dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Barbara Jensen
cn: Barbara J Jensen
cn: Babs Jensen
sn: Jensen
uid: bjensen
telephonenumber: +1 408 555 1212
description: A big sailing fan.

dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Bjorn Jensen
sn: Jensen
telephonenumber: +1 408 555 1212
`

func TestUnmarshalEntries(t *testing.T) {
	t.Run("RFC 2849 example", runTestUnmarshalEntriesRFC2849Example)
	t.Run("empty", runTestUnmarshalEntriesEmpty)

	// no idea what "rainy" was meant to indicate, but ok ...
	t.Run("rainy", runTestUnmarshalEntriesRainy)
}

func TestLDIFParseRFC2849Example(t *testing.T) {
	l, err := ldif.Parse(ldifRFC2849Example)
	if err != nil {
		t.Errorf("Failed to parse RFC 2849 example: %s", err)
	}
	if !l.Entries[1].(ldif.GenericEntry).GetAttributeValues([]byte("sn"))[0].EqualFold(av("Jensen")) {
		t.Errorf("RFC 2849 example: empty 'sn' in second entry")
	}
}

func runTestUnmarshalEntriesEmpty(t *testing.T) {
	var source = strings.NewReader("")
	for e, err := range ldif.UnmarshalEntries(source, &ldif.LDIF{}) {
		if err != nil {
			t.Fatalf("unexpected error while unmarshaling ldif example: %s", err.Error())
		}
		if e == nil {
			t.Fatalf("unexpected nil entry: %s", err.Error())
		}
	}
}

func runTestUnmarshalEntriesRainy(t *testing.T) {
	t.Run("io reader error", func(t *testing.T) {
		var (
			expErr = errors.New("boom")
			source = iotest.ErrReader(expErr)
			ok     bool
		)
		for _, err := range ldif.UnmarshalEntries(source, &ldif.LDIF{}) {
			ok = true
			if err == nil {
				t.Fatal("expected error but got nothing")
			}
			if !strings.Contains(err.Error(), expErr.Error()) {
				t.Fatalf("unexpected error is returned: %#v", err)
			}
		}
		if !ok {
			t.Fatal("error is not propagated back from the iterator")
		}
	})
}

func runTestUnmarshalEntriesRFC2849Example(t *testing.T) {
	var (
		source  = strings.NewReader(ldifRFC2849Example)
		entries []ldif.Entry
	)
	for e, err := range ldif.UnmarshalEntries(source, &ldif.LDIF{}) {
		if err != nil {
			t.Fatalf("unexpected error while unmarshaling ldif example: %s", err.Error())
		}
		entries = append(entries, e)
	}
	if len(entries) < 2 {
		t.Fatalf("expected that after unmarshaling the entries, it should yield results")
	}
	second := entries[1].(ldif.GenericEntry)
	if !second.GetAttributeValues(ad("sn"))[0].EqualFold(av("Jensen")) {
		t.Fatal("RFC 2849 example: empty 'sn' in second entry")
	}
	if _, err := source.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("RFC 2849 example: expected that reader is fully consumed")
	}
}

var ldifEmpty = `dn: uid=someone,dc=example,dc=org
cn:
cn: Some User
`

// RFC 2849 note 5: a zero-length value is represented as "attr:" and MUST be
// supported (e.g. "seeAlso:").
func TestLDIFParseEmptyAttr(t *testing.T) {
	l, err := ldif.Parse(ldifEmpty)
	if err != nil {
		t.Fatalf("Failed to parse empty attribute value: %s", err)
	}
	vals := l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("cn"))
	if len(vals) != 2 {
		t.Fatalf("expected 2 cn values, got %d: %#v", len(vals), vals)
	}
	if len(vals[0]) > 0 {
		t.Errorf("expected first cn value to be empty, got %q", vals[0])
	}
	if !vals[1].Equal(av("Some User")) {
		t.Errorf("expected second cn value %q, got %q", "Some User", vals[1])
	}
}

// RFC 2849 note 5 represents a zero-length value as "AttributeDescription ':'
// FILL SEP", where FILL is *SPACE. So both "seeAlso:" and "seeAlso:   " denote
// an empty value, and they exercise different branches of parseLine (the bare
// colon-terminated line vs. the trailing-space path).
func TestLDIFParseZeroLengthValue(t *testing.T) {
	for name, in := range map[string]string{
		"no fill":   "dn: uid=someone,dc=example,dc=org\nseeAlso:\nsn: Some One\n",
		"with fill": "dn: uid=someone,dc=example,dc=org\nseeAlso:   \nsn: Some One\n",
	} {
		t.Run(name, func(t *testing.T) {
			l, err := ldif.Parse(in)
			if err != nil {
				t.Fatalf("Failed to parse zero-length value: %s", err)
			}
			vals := l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("seeAlso"))
			if len(vals) != 1 || len(vals[0]) > 0 {
				t.Errorf("expected a single empty seeAlso value, got %#v", vals)
			}
		})
	}
}

var ldifChangeThenContent = `dn: cn=a,dc=example,dc=org
changetype: add
cn: a

dn: cn=b,dc=example,dc=org
cn: b
sn: b
`

// A record without a changetype must be parsed as a content entry regardless of
// what the previous record's changetype was: the parser must not carry the
// changetype across records.
func TestLDIFChangeTypeNotLeaked(t *testing.T) {
	l, err := ldif.Parse(ldifChangeThenContent)
	if err != nil {
		t.Fatalf("Failed to parse: %s", err)
	}
	if ch := l.Entries[0].Choice(); ch != "addRequest" {
		t.Fatalf("first record should be an add request")
	}
	if ch := l.Entries[1].Choice(); ch == "addRequest" {
		t.Errorf("changetype leaked: second record parsed as an add request")
	}
	if ch := l.Entries[1].Choice(); ch != "entry" {
		t.Fatalf("second record should be a content entry, not %#v", l.Entries[1])
	}
	if dn := l.Entries[1].DN().String(); dn != "cn=b,dc=example,dc=org" {
		t.Errorf("wrong dn on second entry: %q", dn)
	}
	if cn := l.Entries[1].(ldif.GenericEntry).GetAttributeValue(ad("cn")); !cn.Equal(av("b")) {
		t.Errorf("wrong cn on second entry: %q", cn)
	}
}

var ldifMissingDN = `objectclass: top
cn: Some User
`

func TestLDIFParseMissingDN(t *testing.T) {
	_, err := ldif.Parse(ldifMissingDN)
	if err == nil {
		t.Errorf("Did not fail to parse missing DN attribute")
	}
}

var ldifContinuation = `dn: uid=someone,dc=example,dc=org
sn: Some
  One
cn: Someone
`

func TestLDIFContinuation(t *testing.T) {
	l, err := ldif.Parse(ldifContinuation)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	e := l.Entries[0]
	if !e.(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0].Equal(av("Some One")) {
		t.Errorf("Value of continuation line wrong")
	}
}

var ldifBase64 = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=
`

func TestLDIFBase64(t *testing.T) {
	l, err := ldif.Parse(ldifBase64)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}

	e := l.Entries[0]
	val := e.(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0]
	cmp := av("Some One")
	if !val.Equal(cmp) {
		t.Errorf("Value of base64 value wrong: >%v< >%v<", []byte(val), []byte(cmp))
	}
}

var ldifBase64Broken = `dn: uid=someone,dc=example,dc=org
sn:: XXX-U29tZSBPbmU=
`

func TestLDIFBase64Broken(t *testing.T) {
	_, err := ldif.Parse(ldifBase64Broken)
	if err == nil {
		t.Errorf("Did not failed to parse broken base64")
	}
}

var ldifTrailingBlank = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=

`

func TestLDIFTrailingBlank(t *testing.T) {
	_, err := ldif.Parse(ldifTrailingBlank)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
}

var ldifComments = `dn: uid=someone,dc=example,dc=org
# a comment
 continued comment
sn: someone
`

func TestLDIFComments(t *testing.T) {
	l, err := ldif.Parse(ldifComments)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if !l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0].Equal(av("someone")) {
		t.Errorf("No sn attribute")
	}
}

var ldifNoSpace = `dn:uid=someone,dc=example,dc=org
sn:someone
`

func TestLDIFNoSpace(t *testing.T) {
	l, err := ldif.Parse(ldifNoSpace)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if !l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0].Equal(av("someone")) {
		t.Errorf("No/wrong sn attribute: '%s'", l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0])
	}
}

var ldifMultiSpace = `dn:  uid=someone,dc=example,dc=org
sn:    someone
`

func TestLDIFMultiSpace(t *testing.T) {
	l, err := ldif.Parse(ldifMultiSpace)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if !l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0].Equal(av("someone")) {
		t.Errorf("No/wrong sn attribute: '%s'", l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("sn"))[0])
	}
}

func TestLDIFURL(t *testing.T) {
	f, err := os.CreateTemp("", "ldifurl")
	if err != nil {
		t.Errorf("Failed to create temp file: %s", err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("TEST\n"))
	f.Sync()
	l, err := ldif.Parse("dn: uid=someone,dc=example,dc=org\ndescription:< file:///" + f.Name() + "\n")
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if !l.Entries[0].(ldif.GenericEntry).GetAttributeValues(ad("description"))[0].Equal(av("TEST\n")) {
		t.Errorf("wrong file?")
	}
}

var ldifMultiBlankLines = `# Organization Units
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: users


# searches for above empty line for dn but fails and errors out in this PR
# Even though this is a valid LDIF file for ldapadd
dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: groups
`

func TestLDIFMultiBlankLines(t *testing.T) {
	l, err := ldif.Parse(ldifMultiBlankLines)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	ou := l.Entries[1].(ldif.GenericEntry).GetAttributeValue(ad("ou"))
	if !ou.Equal(av("groups")) {
		t.Errorf("wrong ou in second entry: %s", ou)
	}
}

var ldifLeadingTrailingBlankLines = `

# Organization Units
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: users


`

func TestLDIFLeadingTrailingBlankLines(t *testing.T) {
	l, err := ldif.Parse(ldifLeadingTrailingBlankLines)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	ou := l.Entries[0].(ldif.GenericEntry).GetAttributeValue(ad("ou"))
	if !ou.Equal(av("users")) {
		t.Errorf("wrong ou in entry: %s", ou)
	}
}

var ldifVersionOnSecond = `dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Barbara Jensen
cn: Barbara J Jensen
cn: Babs Jensen
sn: Jensen
uid: bjensen
telephonenumber: +1 408 555 1212
description: A big sailing fan.

version: 1
dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Bjorn Jensen
sn: Jensen
telephonenumber: +1 408 555 1212
`

func TestLDIFVersionOnSecond(t *testing.T) {
	if _, err := ldif.Parse(ldifVersionOnSecond); err == nil {
		t.Errorf("did not fail to parse LDIF")
	}
}

const ldifModify = `dn: uid=someone,ou=people,dc=example,dc=org
changetype: modify
add: givenName
givenName: Some1
givenName: Some2
-
delete: mail
-
delete: telephoneNumber
telephoneNumber: 123 456 789 - 0
-
replace: sn
sn: One
-

`

func TestParseModify(t *testing.T) {
	l, err := ldif.Parse(ldifModify)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}

	if actual := len(l.Entries); actual != 1 {
		t.Error("Expected", 1, "Actual", actual)
	}

	// Delete attributes
	attributes := countChangeType("delete", l.Entries[0].(*ldif.ModifyRequest).Changes)
	testParseModifyDelAttr(t, attributes)

	// Replace attributes
	attributes = countChangeType("replace", l.Entries[0].(*ldif.ModifyRequest).Changes)
	testParseModifyRepAttr(t, attributes)

	// Add attributes
	attributes = countChangeType("add", l.Entries[0].(*ldif.ModifyRequest).Changes)
	testParseModifyAddAttr(t, attributes)
}

func testParseModifyDelAttr(t *testing.T, attributes []ldif.ModifyRequestChange) {
	if actual := len(attributes); actual != 2 {
		t.Error("Expected", 2, "Actual", actual)
	}

	if actual := attributes[0].Modification.Type; !actual.Equal(ad("mail")) {
		t.Error("Expected", "mail", "Actual", actual)
	}

	if actual := len(attributes[0].Modification.Vals[0]); actual != 0 {
		t.Error("Expected", 0, "Actual", actual)
	}

	if actual := attributes[1].Modification.Type; !actual.Equal(ad("telephoneNumber")) {
		t.Error("Expected", "telephoneNumber", "Actual", actual)
	}

	if actual := len(attributes[1].Modification.Vals); actual != 1 {
		t.Error("Expected", 1, "Actual", actual)
	}

	if actual := attributes[1].Modification.Vals[0]; !actual.Equal(av("123 456 789 - 0")) {
		t.Error("Expected", "123 456 789 - 0", "Actual", actual)
	}
}

func testParseModifyRepAttr(t *testing.T, attributes []ldif.ModifyRequestChange) {
	if actual := len(attributes); actual != 1 {
		t.Error("Expected", 1, "Actual", actual)
	}

	if actual := attributes[0].Modification.Type; !actual.Equal(ad("sn")) {
		t.Error("Expected", "sn", "Actual", actual)
	}

	if actual := len(attributes[0].Modification.Vals); actual != 1 {
		t.Error("Expected", 1, "Actual", actual)
	}

	if actual := attributes[0].Modification.Vals[0]; !actual.Equal(av("One")) {
		t.Error("Expected", "One", "Actual", actual)
	}
}

func testParseModifyAddAttr(t *testing.T, attributes []ldif.ModifyRequestChange) {
	if actual := len(attributes); actual != 1 {
		t.Error("Expected", 1, "Actual", actual)
	}

	if actual := attributes[0].Modification.Type; !actual.Equal(ad("givenName")) {
		t.Error("Expected", "givenName", "Actual", actual)
	}

	if actual := len(attributes[0].Modification.Vals); actual != 2 {
		t.Error("Expected", 2, "Actual", actual)
	}

	if actual := attributes[0].Modification.Vals[0]; !actual.Equal(av("Some1")) {
		t.Error("Expected", "Some1", "Actual", actual)
	}

	if actual := attributes[0].Modification.Vals[1]; !actual.Equal(av("Some2")) {
		t.Error("Expected", "Some2", "Actual", actual)
	}
}

// countChangeType is a helper function to minimise test changes migrating to ldapv3
func countChangeType(typ string, ch []ldif.ModifyRequestChange) []ldif.ModifyRequestChange {
	var t = map[string]uint{
		"add":     0,
		"delete":  1,
		"replace": 2,
	}
	c := []ldif.ModifyRequestChange{}
	for _, i := range ch {
		if uint(i.Operation) == t[typ] {
			c = append(c, i)
		}
	}
	return c
}
