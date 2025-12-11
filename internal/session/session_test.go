package session

import (
	"reflect"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: mcpe-server-proxy, Property 8: Session Data Round-Trip**
// **Validates: Requirements 4.7, 4.8**
// For any session record, serializing to JSON and deserializing back
// SHALL produce an equivalent session record.
func TestSessionRecordRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Session record JSON round-trip preserves data", prop.ForAll(
		func(id, clientAddr, serverID, uuid, displayName, metadata string,
			bytesUp, bytesDown int64,
			startYear, startMonth, startDay, startHour, startMin, startSec int,
			endYear, endMonth, endDay, endHour, endMin, endSec int) bool {

			// Construct valid time values
			startTime := time.Date(
				2020+startYear%10, time.Month(1+startMonth%12), 1+startDay%28,
				startHour%24, startMin%60, startSec%60, 0, time.UTC)
			endTime := time.Date(
				2020+endYear%10, time.Month(1+endMonth%12), 1+endDay%28,
				endHour%24, endMin%60, endSec%60, 0, time.UTC)

			// Ensure bytesUp and bytesDown are non-negative
			if bytesUp < 0 {
				bytesUp = -bytesUp
			}
			if bytesDown < 0 {
				bytesDown = -bytesDown
			}

			original := &SessionRecord{
				ID:          id,
				ClientAddr:  clientAddr,
				ServerID:    serverID,
				UUID:        uuid,
				DisplayName: displayName,
				BytesUp:     bytesUp,
				BytesDown:   bytesDown,
				StartTime:   startTime,
				EndTime:     endTime,
				Metadata:    metadata,
			}

			// Serialize to JSON
			jsonData, err := original.ToJSON()
			if err != nil {
				t.Logf("Serialization failed: %v", err)
				return false
			}

			// Deserialize from JSON
			restored, err := SessionRecordFromJSON(jsonData)
			if err != nil {
				t.Logf("Deserialization failed: %v", err)
				return false
			}

			// Verify all fields match
			return original.ID == restored.ID &&
				original.ClientAddr == restored.ClientAddr &&
				original.ServerID == restored.ServerID &&
				original.UUID == restored.UUID &&
				original.DisplayName == restored.DisplayName &&
				original.BytesUp == restored.BytesUp &&
				original.BytesDown == restored.BytesDown &&
				original.StartTime.Equal(restored.StartTime) &&
				original.EndTime.Equal(restored.EndTime) &&
				original.Metadata == restored.Metadata
		},
		gen.AlphaString(),        // id
		gen.AlphaString(),        // clientAddr
		gen.AlphaString(),        // serverID
		gen.AlphaString(),        // uuid
		gen.AlphaString(),        // displayName
		gen.AlphaString(),        // metadata
		gen.Int64Range(0, 1<<50), // bytesUp
		gen.Int64Range(0, 1<<50), // bytesDown
		gen.IntRange(0, 100),     // startYear offset
		gen.IntRange(0, 11),      // startMonth
		gen.IntRange(0, 27),      // startDay
		gen.IntRange(0, 23),      // startHour
		gen.IntRange(0, 59),      // startMin
		gen.IntRange(0, 59),      // startSec
		gen.IntRange(0, 100),     // endYear offset
		gen.IntRange(0, 11),      // endMonth
		gen.IntRange(0, 27),      // endDay
		gen.IntRange(0, 23),      // endHour
		gen.IntRange(0, 59),      // endMin
		gen.IntRange(0, 59),      // endSec
	))

	properties.TestingRun(t)
}

// **Feature: xbox-live-auth-proxy, Property 3: Player Identity Extraction Completeness**
// **Validates: Requirements 2.1, 2.2, 2.3, 2.5**
// For any client connection with identity data containing uuid, display_name, and xuid,
// the proxy SHALL extract all three fields and store them in the session record.
func TestProperty_PlayerIdentityExtractionCompleteness(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	// Generator for UUID-like strings (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
	uuidGen := gen.SliceOfN(32, gen.AlphaNumChar()).Map(func(chars []rune) string {
		s := string(chars)
		return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
	})

	// Generator for XUID-like strings (numeric string, typically 16 digits)
	xuidGen := gen.SliceOfN(16, gen.NumChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for display names (alphanumeric, 3-16 characters)
	// Using SliceOfN to ensure we always get valid length strings
	displayNameGen := gen.IntRange(3, 16).FlatMap(func(length interface{}) gopter.Gen {
		return gen.SliceOfN(length.(int), gen.AlphaNumChar()).Map(func(chars []rune) string {
			return string(chars)
		})
	}, reflect.TypeOf(""))

	properties.Property("All identity fields (uuid, display_name, xuid) are extracted and stored", prop.ForAll(
		func(uuid, displayName, xuid, clientAddr, serverID string) bool {
			// Create a new session
			session := &Session{
				ID:         "test-session-id",
				ClientAddr: clientAddr,
				ServerID:   serverID,
				StartTime:  time.Now(),
				LastSeen:   time.Now(),
			}

			// Simulate identity extraction by calling SetPlayerInfoWithXUID
			// This is what the MITM proxy does when a client connects
			session.SetPlayerInfoWithXUID(uuid, displayName, xuid)

			// Property 1: UUID is correctly stored
			if session.UUID != uuid {
				t.Logf("UUID mismatch: expected %s, got %s", uuid, session.UUID)
				return false
			}

			// Property 2: DisplayName is correctly stored
			if session.DisplayName != displayName {
				t.Logf("DisplayName mismatch: expected %s, got %s", displayName, session.DisplayName)
				return false
			}

			// Property 3: XUID is correctly stored
			if session.XUID != xuid {
				t.Logf("XUID mismatch: expected %s, got %s", xuid, session.XUID)
				return false
			}

			// Property 4: LoginExtracted flag is set
			if !session.IsLoginExtracted() {
				t.Logf("LoginExtracted should be true after setting player info")
				return false
			}

			// Property 5: All fields are accessible via getter
			if session.GetXUID() != xuid {
				t.Logf("GetXUID() mismatch: expected %s, got %s", xuid, session.GetXUID())
				return false
			}

			// Property 6: DTO contains all identity fields
			dto := session.ToDTO()
			if dto.UUID != uuid || dto.DisplayName != displayName || dto.XUID != xuid {
				t.Logf("DTO field mismatch: UUID=%s/%s, DisplayName=%s/%s, XUID=%s/%s",
					uuid, dto.UUID, displayName, dto.DisplayName, xuid, dto.XUID)
				return false
			}

			return true
		},
		uuidGen,
		displayNameGen,
		xuidGen,
		gen.AlphaString().Map(func(s string) string { return s + ":12345" }), // clientAddr
		gen.AlphaString(), // serverID
	))

	properties.TestingRun(t)
}

// TestProperty_SessionRecordWithXUID tests that SessionRecord correctly includes XUID field.
// **Feature: xbox-live-auth-proxy, Property 3: Player Identity Extraction Completeness**
// **Validates: Requirements 2.5**
func TestProperty_SessionRecordWithXUID(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	// Generator for XUID-like strings
	xuidGen := gen.SliceOfN(16, gen.NumChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	properties.Property("SessionRecord with XUID round-trips correctly", prop.ForAll(
		func(id, clientAddr, serverID, uuid, displayName, xuid string,
			bytesUp, bytesDown int64) bool {

			// Ensure bytesUp and bytesDown are non-negative
			if bytesUp < 0 {
				bytesUp = -bytesUp
			}
			if bytesDown < 0 {
				bytesDown = -bytesDown
			}

			original := &SessionRecord{
				ID:          id,
				ClientAddr:  clientAddr,
				ServerID:    serverID,
				UUID:        uuid,
				DisplayName: displayName,
				XUID:        xuid,
				BytesUp:     bytesUp,
				BytesDown:   bytesDown,
				StartTime:   time.Now().UTC().Truncate(time.Second),
				EndTime:     time.Now().UTC().Truncate(time.Second),
			}

			// Serialize to JSON
			jsonData, err := original.ToJSON()
			if err != nil {
				t.Logf("Serialization failed: %v", err)
				return false
			}

			// Deserialize from JSON
			restored, err := SessionRecordFromJSON(jsonData)
			if err != nil {
				t.Logf("Deserialization failed: %v", err)
				return false
			}

			// Verify XUID is preserved
			if original.XUID != restored.XUID {
				t.Logf("XUID mismatch after round-trip: expected %s, got %s",
					original.XUID, restored.XUID)
				return false
			}

			// Verify all other fields are also preserved
			return original.ID == restored.ID &&
				original.ClientAddr == restored.ClientAddr &&
				original.ServerID == restored.ServerID &&
				original.UUID == restored.UUID &&
				original.DisplayName == restored.DisplayName &&
				original.XUID == restored.XUID &&
				original.BytesUp == restored.BytesUp &&
				original.BytesDown == restored.BytesDown
		},
		gen.AlphaString(),        // id
		gen.AlphaString(),        // clientAddr
		gen.AlphaString(),        // serverID
		gen.AlphaString(),        // uuid
		gen.AlphaString(),        // displayName
		xuidGen,                  // xuid
		gen.Int64Range(0, 1<<50), // bytesUp
		gen.Int64Range(0, 1<<50), // bytesDown
	))

	properties.TestingRun(t)
}
