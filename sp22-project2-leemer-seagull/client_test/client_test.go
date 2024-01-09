package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite"
const contentTwo = "digital"
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// // //var mary *client.User
	var anna *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	bobFileOwnedByHim := "bobFileOwnedByHim.txt"
	charlesFile := "charlesFile.txt"
	// // //maryFile := "maryFile.txt"
	annaFile := "annaFile.txt"
	// //dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing InitUser/GetUser on multilple users.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Bob.")
			aliceLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			alice, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Charles.")
			aliceLaptop, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Multiple User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			// operations for User Bob
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Testing Sharing and Revoking with multiple users.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charles, and Anna")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			anna, err = client.InitUser("anna", defaultPassword)
			Expect(err).To(BeNil())

			// 1) alice stores the file
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			// 2) alice shares this file with 2 people - bob & charles : checks that you create 2 unqiue invites s.t. revoking for one does not revoke for both
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			inviteForBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			inviteForCharles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			// 3) charles and bob accept the invites
			err = bob.AcceptInvitation("alice", inviteForBob, bobFile)
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", inviteForCharles, charlesFile)
			Expect(err).To(BeNil())

			// 4) charles (not the fileowner) shared with ana (the same file he got from Alice)
			userlib.DebugMsg("Charles creating invite for Anna for file %s, and Anna accepting invite under name %s.", charlesFile, annaFile)
			inviteForAnna, err := charles.CreateInvitation(charlesFile, "anna")
			Expect(err).To(BeNil())

			// 5) anna accepts the invite
			err = anna.AcceptInvitation("charles", inviteForAnna, annaFile)
			Expect(err).To(BeNil())

			// 5) anna loads this shared file - testing if a shared user can open the shared file
			userlib.DebugMsg("Checking that Anna can load the file.")
			data, err := anna.LoadFile(annaFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// 6) alice revokes bob
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			
			// 7) check if alice + ana + charles can load the file
			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can still load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Anna can still load the file.")
			data, err = anna.LoadFile(annaFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// ** expectation: ana and charles can STILL open the file since they STILL have access 
		})

		Specify("Basic Test: Testing Sharing and Revoking with multiple users 2.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charles, Anna")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			anna, err = client.InitUser("anna", defaultPassword)
			Expect(err).To(BeNil())

			// 1) alice stores the file
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			// 2) alice shares this file with bob
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			inviteForBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// 3) bob accept the invite from alice
			err = bob.AcceptInvitation("alice", inviteForBob, bobFile)
			Expect(err).To(BeNil())

			// 4) bob (not the fileowner) shares alice's file with Anna 
			userlib.DebugMsg("Bob creating invite for Anna for file %s, and Anna accepting invite under name %s.", bobFile, annaFile)
			inviteForAnna, err := bob.CreateInvitation(bobFile, "anna")
			Expect(err).To(BeNil())

			// 5) anna accepts the invite
			err = anna.AcceptInvitation("bob", inviteForAnna, annaFile)
			Expect(err).To(BeNil())

			// 6) bob stores his own file
			userlib.DebugMsg("Bob storing file %s with content: %s", bobFileOwnedByHim, contentTwo)
			bob.StoreFile(bobFileOwnedByHim, []byte(contentTwo))

			// 7) bob shares his OWN file with charles
			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFileOwnedByHim, charlesFile)
			inviteForCharles, err := bob.CreateInvitation(bobFileOwnedByHim, "charles")
			Expect(err).To(BeNil())

			// 8) charles accepts the invite
			err = charles.AcceptInvitation("bob", inviteForCharles, charlesFile)
			Expect(err).To(BeNil())			

			// 9) bob revokes access for charles
			userlib.DebugMsg("Bob revoking Charles's access from %s.", bobFileOwnedByHim)
			err = bob.RevokeAccess(bobFileOwnedByHim, "charles")
			Expect(err).To(BeNil())
			
			// 11) charles tries to load Bob's file - SHOULD FAIL
			userlib.DebugMsg("Checking that Charles can still load the file.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			// 12) anna tries to load Alice's file - SHOULD PASS
			userlib.DebugMsg("Checking that Anna can still load the file.")
			data, err := anna.LoadFile(annaFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Basic Test: Testing that shared users can store/load/append.", func() { 
			userlib.DebugMsg("Initializing users Alice, Bob, Charles & Anna")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			anna, err = client.InitUser("anna", defaultPassword)
			Expect(err).To(BeNil())

			// 1) alice stores the file
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			// 2) alice shares this file with bob
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			inviteForBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// 3) bob accepts the invite from alice
			err = bob.AcceptInvitation("alice", inviteForBob, bobFile)
			Expect(err).To(BeNil())

			// 4) bob stores alice's file
			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			bob.StoreFile(bobFile, []byte(contentOne))

			// 5) bob appends alice's file
			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			// 6) bob loads alice's file
			userlib.DebugMsg("Loading file...")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			// 7) alice loads her own file
			// bob re-stores the same file with his argon2key so NOW alice cannot open it since the file was re-encrypted with bob's unique, privKey
			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing all cases for store, load, & append.", func() { 
			userlib.DebugMsg("Initializing users Alice & Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// CASE 1: alice tries to store her own file for the FIRST TIME
			// 1) alice stores her own file
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			// 2) alice tries to append to her OWN file
			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			// 3) alice tries to load her own file
			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			// CASE #2: bob (not the fileowner) tries to store/overwrite Alice's file
			// 1) alice shares with bob
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			inviteForBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			// 2) bob accepts the invite
			err = bob.AcceptInvitation("alice", inviteForBob, bobFile)
			Expect(err).To(BeNil())
			// 3) bob stores the file (which is Alice's file)
			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			bob.StoreFile(bobFile, []byte(contentTwo)) // overwrite content 1 (alice's original content) with content 2
			// 4) bob tries to append to alice's file
			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())
			// 4) bob loads the file
			userlib.DebugMsg("Loading file...")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))
			// 4) alice loads her file (she needs to still have access to her own file)
			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			// CASE #3: alice tries to overwrite her own file 
			// 1) alices restores her own file
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentThree)
			alice.StoreFile(aliceFile, []byte(contentThree))
			// 2) alice tries to load her own file
			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			// 3) bob loads the file
			userlib.DebugMsg("Loading file...")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})

		Specify("Design Requirement 3.1: usernames & passwords", func() {
			// CASE #1: unique usernames
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice AGAIN.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil()) // should error because we cannot have two users with the same username

			// CASE #2: lower and upper case are two unique users
			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob AGAIN.")
			anna, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil()) // should NOT error because we can have users "bob" and "Bob" 

			// CASE #3: usernames cannot be < len of 1
			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil()) // should error bc len of username is < 1

			// CASE #4: password of length 0
			userlib.DebugMsg("Initializing user Anna.")
			password := ""
			anna, err = client.InitUser("Anna", password)
			Expect(err).To(BeNil())

			// CASE #5: passwords do NOT need to be unique
			userlib.DebugMsg("Initializing user Doris.")
			userlib.DebugMsg("Initializing user Eve.")
			password = "hi" // use the same password
			_, err := client.InitUser("Doris", password)
			Expect(err).To(BeNil())
			_, err = client.InitUser("Eve", password)
			Expect(err).To(BeNil())
		})

		Specify("Design Requirement 3.2: user sessions", func() { 
			// NEED to do this
		})

		Specify("Design Requirement 3.5: files", func() { 
			// Filenames do NOT need to be unique 
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Anna.")
			anna, err = client.InitUser("anna", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", bobFile, contentTwo)
			err = alice.StoreFile(bobFile, []byte(contentTwo)) 
			Expect(err).To(BeNil()) 

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			
			// File lengths can be 0
			annaFileEmpty := ""
			userlib.DebugMsg("Anna storing file %s with content: %s", annaFileEmpty, contentTwo)
			anna.StoreFile(annaFileEmpty, []byte(contentTwo))

			// users can NOT have files with the SAME filenames
			// 1) Bob shares his file (with the same name) with Anna
			userlib.DebugMsg("Bob creating invite for Anna for file %s, and Anna accepting invite under name %s.", bobFile, annaFile)
			inviteForAnna, err := bob.CreateInvitation(bobFile, "anna")
			Expect(err).To(BeNil())

			// 3) Anna accepting this invite from Bob 
			err = anna.AcceptInvitation("bob", inviteForAnna, annaFile)
			Expect(err).To(BeNil())

			// 4) Alice sharing her file with Anna
			userlib.DebugMsg("Alice creating invite for Anna for file %s, and Anna accepting invite under name %s.", bobFile, annaFile)
			inviteForAnna, err = alice.CreateInvitation(bobFile, "anna")
			Expect(err).To(BeNil())

			// 4) Anna accepting this invite from Alice - FAIL bc she cannot have two files with the same name
			err = anna.AcceptInvitation("alice", inviteForAnna, annaFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Design Requirement 3.6: files", func() { 
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			alice.StoreFile(aliceFile, []byte(contentTwo))
			
			// TEST: The client MUST prevent any revoked user from using the client API
			// 1) alice shares with bob
			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			inviteForBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// 2) bob accepts the invite
			err = bob.AcceptInvitation("alice", inviteForBob, bobFile)
			Expect(err).To(BeNil())

			// 3) alice revokes access for bob
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			// 4) bob tries to store, load, append, create and revoke
			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne)) 
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(contentOne + contentThree)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s.", bobFile)
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob revoking Charles's access from %s.", bobFile)
			err = bob.RevokeAccess(bobFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Design Requirement 3.3: cryptography and keys", func() {
			userlib.DebugMsg("Initializing user Bob.")
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil()) 

			userlib.DebugMsg("Getting user Bob.")
			_, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// CHECK #1: A single user MAY have multiple entries in Keystore.
			var keyMap map[string]userlib.PublicKeyType = userlib.KeystoreGetMap()
			var sizeOfMap int = len(keyMap)
			var lenGreaterThan1 bool = sizeOfMap > 1
			Expect(lenGreaterThan1).ToNot(BeFalse())

			// However, the number of keys in Keystore per user MUST be a small constant;
			// it MUST NOT depend on the number of files stored or length of any file,
			// how many users a file has been shared with, or the number of users already in the system.
		})

	})
})

