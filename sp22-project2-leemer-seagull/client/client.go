package client
// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	//"golang.org/x/crypto/nacl/auth"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// **** HELPER METHODS ****

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username          string
	Password          string
	PrivateKey        []byte                 // this is the argon key - symmetric encryption
	PrivateKeyGen     userlib.PrivateKeyType // RSA key for public key encryption
	PublicKey         userlib.PKEEncKey      // RSA key for public key encryption
	PrivateKeyForDS   userlib.DSSignKey      // RSA key for signing
	PublicKeyForDS    userlib.DSVerifyKey    // RSA key for signing
	FilesSharedByMe   map[string]uuid.UUID   // map the recipientUsername/filename to the intermediate struct's UUID (location)
	RandomNum		  int
	FilesSharedWithMe map[string]uuid.UUID   // map the username/filename to the intermediate struct's UUID (location)
	MyFiles 		  []string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileLinkedList struct {
	FirstPTR  uuid.UUID
	LastPTR   uuid.UUID
	//FileOwner string
}

type FileDataNode struct {
	Filename string
	FileData []byte
	NextPTR  uuid.UUID
}

type Invitation struct {
	//HMAC    []byte
	NextPTR    uuid.UUID // pointer to the lockbox
	PrivateKey []byte    // this is the argon2key
}

type Intermediate struct {
	NextPTR      uuid.UUID
	PrivateKey   []byte
	LockBoxOwner string
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// CREATE STRUCT USER
	var userdata User // create a struct called user

	// ERROR CHECK #1 - empty string
	if len(username) == 0 {
		return nil, errors.New("empty string inputted")
	}

	// HASH THE USERNAME - users with the same first 16 letters may map to same value so we should hash full username
	// CREATE THE UUID - for the username
	usernameUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[0:16]) // https://www.geeksforgeeks.org/slices-in-golang/
	if err != nil {
		return nil, errors.New("error: username failed")
	}
	// ERROR CHECK #2 - username is already taken
	_, ok := userlib.DatastoreGet(usernameUUID)
	if ok != false {
		return nil, errors.New("username already taken")
	}

	// CREATE THE KEY - creates a key from the specific username, the salt here is the username (bc username is unique)
	// source - https://gosamples.dev/string-byte-slice/#:~:text=To%20convert%20a%20string%20to,the%20string(%5B%5Dbyte)%20conversion.
	dataStoreKey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// UPDATE THE USER'S ATTRIBUTES - setting them
	userdata.Username = username
	userdata.PrivateKey = dataStoreKey
	userdata.Password = password
	userdata.FilesSharedWithMe = make(map[string]uuid.UUID)
	userdata.FilesSharedByMe = make(map[string]uuid.UUID)
	userdata.MyFiles = make([]string, 0)
	userdata.RandomNum = 2

	// CREATE A PUBLIC KEY
	publicKey, privateKeyGen, err := userlib.PKEKeyGen() // you also need to store the private key here
	if err != nil {
		return nil, errors.New("error: key creation for public key encryption failed")
	}
	userdata.PublicKey = publicKey
	userdata.PrivateKeyGen = privateKeyGen // save the private key from public key encryption in the USER struct

	// CREATE DS keys
	rsaPrivateKey, rsaPublicKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("error2")
	}
	userdata.PrivateKeyForDS = rsaPrivateKey
	userdata.PublicKeyForDS = rsaPublicKey

	// MARSHALL THE USER STRUCT
	marshalledStruct, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("error: marshal failed for struct")
	}

	// ENCRYPT THE STRUCT - encrypt the marshalled struct (the plaintext)
	encryptedStruct := userlib.SymEnc(dataStoreKey, userlib.RandomBytes(16), marshalledStruct)
	privateKeyForHMAC, err := userlib.HashKDF(dataStoreKey, []byte(username))
	if err != nil {
		return nil, errors.New("error: private key for hmac failed")
	}
	// "ENCRYPT THEN MAC" approach - mac over the ciphertext
	hmac, err := userlib.HMACEval(privateKeyForHMAC[:16], encryptedStruct)
	if err != nil {
		return nil, errors.New("error: hmac creation failed")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedStructWithHMAC := append(encryptedStruct, hmac...)

	// STORE THE VALUE & KEY - value (encryptedStructWithHMAC) and key (UUID)
	userlib.DatastoreSet(usernameUUID, encryptedStructWithHMAC)
	// ADD THE PUBLIC KEY FOR DS TO THE KEYSTORE
	userlib.KeystoreSet(username+"signKey", rsaPublicKey)
	// ADD THE PUBLIC KEY FOR ENCRYPTING TO THE KEYSTORE
	userlib.KeystoreSet(username+"encryptKey", publicKey)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// ERROR CHECK #1 - empty string
	if len(username) == 0 {
		return nil, errors.New("error: empty string")
	}

	// CREATE THE KEY - retrieve the one stored in the user struct
	dataStoreKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	// CREATE THE UUID (FROM THE KEY)
	deterministicUUID, _ := uuid.FromBytes(userlib.Hash([]byte(username))[0:16])

	// ERROR CHECK #2 - There is no initialized user for the given username.
	encryptedStructWithHMAC, ok := userlib.DatastoreGet(deterministicUUID) // GET THE VALUE (user struct)
	if ok == false {
		return nil, errors.New("error: no initialized user")
	}

	// EXTRACT THE USER STRUCT - splice to get the user struct
	extractEncryptedUserStruct := encryptedStructWithHMAC[0 : len(encryptedStructWithHMAC)-64] // HMACS ARE 64 bytes long!!

	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err := userlib.HashKDF(dataStoreKey, []byte(username))
	if err != nil {
		return nil, errors.New("error: hmac creation failed")
	}
	tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedUserStruct)
	if err != nil {
		return nil, errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC := encryptedStructWithHMAC[len(encryptedStructWithHMAC)-64 : len(encryptedStructWithHMAC)]

	// ERROR CHECKS #3 + #4: user struct malicious action/integrity compromised AND user creditials are invalid
	authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return nil, errors.New("user struct was tampered - line 248")
	}

	// DECRYPT THE USER STRUCT
	decryptedUserStruct := userlib.SymDec(dataStoreKey, extractEncryptedUserStruct) // decrypt the user struct with the given user key

	// UNMARSHALL THE USER STRUCT
	var userdata User
	err = json.Unmarshal(decryptedUserStruct, &userdata)
	if err != nil {
		return nil, errors.New("error: unmarshal failed")
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// ------------------------------------ FILE OWNER CHECK ------------------------------------
	intermediateUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return errors.New("error: hashing the UUID failed - 285")
	}
	encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID) // gives you the intermediate struct
	if ok == true { // if YOU ARE THE FILE OWNER and you are trying to overwrite your own file that already exists
		//------------------------------------ SYMMETRICALLY DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
		// CHECK HMACS: authenticity/integrity check
		extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
		intermediateHMACRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)                                                               // key to symmetrically DECRYPT the intermediate
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
		if err != nil {
			return errors.New("error: hmac creation failed 611")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
		if err != nil {
			return errors.New("error: hmac failed 2")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return errors.New("user struct was tampered with: line ")
		}
		privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) 
		if err != nil {
			return errors.New("user struct was tampered with: 849")
		}
		// DECRYPT THE INTERMEDIATE STRUCT
		decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
		// UNMARSHALL THE INTERMEDIATE STRUCT
		var userIntermediateStruct Intermediate
		err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
		if err != nil {
			return errors.New("error: unmarshal failed: 859")
		}
		linkedListLocation := userIntermediateStruct.NextPTR // this points to "Alice's" LL file struct
		linkedListArgon2Key := userIntermediateStruct.PrivateKey // argon2key

		// -------------------- CREATE THE LINKEDLIST STRUCT AND STORE IT IN DATASTORE to override the original file --------------------
		var fileLinkedList FileLinkedList
		firstNodeUUID := uuid.New()
		fileLinkedList.FirstPTR = firstNodeUUID // set this to the first file node
		nextNodeUUID := uuid.New()
		fileLinkedList.LastPTR = nextNodeUUID // set the last pointer to the nextNode (location in memory)

		linkedListRootKey := linkedListArgon2Key
		privateKeyForLinkedListStruct, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL")) 
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// MARSHALL THE FILE LINKED LIST STRUCT
		marshalledLinkedListStruct, err := json.Marshal(fileLinkedList)
		if err != nil {
			return errors.New("error: marshal failed")
		}
		// ENCRYPT THE FILE LINKED LIST STRUCT
		encryptedLinkedListStruct := userlib.SymEnc(privateKeyForLinkedListStruct[:16], userlib.RandomBytes(16), marshalledLinkedListStruct)
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		privateKeyForLinkedListHMAC, err := userlib.HashKDF(linkedListRootKey, []byte("HMACforLL"))
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		HMACforLinkedList, err := userlib.HMACEval(privateKeyForLinkedListHMAC[:16], encryptedLinkedListStruct)
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedLinkedListStructWithHMAC := append(encryptedLinkedListStruct, HMACforLinkedList...)

		// SET - key: random UUID, value: linkedlist
		userlib.DatastoreSet(linkedListLocation, encryptedLinkedListStructWithHMAC)

		// ----------------------------------------- CREATE THE FILE NODE STRUCT ---------------------------------------------------
		var fileNode FileDataNode
		fileNode.Filename = filename
		fileNode.FileData = content
		fileNode.NextPTR = nextNodeUUID // the next node of the file node = next node of the file linked list

		fileNodeRootKey := linkedListArgon2Key
		privateKeyForFileNodeStruct, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode")) // PURPOSE: username/filename
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// MARSHALL THE FILE NODE STRUCT
		marshalledFileStruct, err := json.Marshal(fileNode)
		if err != nil {
			return errors.New("error: marshal failed")
		}
		// ENCRYPT THE FILE NODE STRUCT
		encryptedFileStruct := userlib.SymEnc(privateKeyForFileNodeStruct[:16], userlib.RandomBytes(16), marshalledFileStruct)
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		privateKeyForFileNodeHMAC, err := userlib.HashKDF(fileNodeRootKey, []byte("HMACforFileNode")) // PURPOSE: username-filename
		HMAC, err := userlib.HMACEval(privateKeyForFileNodeHMAC[:16], encryptedFileStruct)
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedFileStructWithHMAC := append(encryptedFileStruct, HMAC...)

		// SET - place this key (file node): key = firstNode location
		userlib.DatastoreSet(firstNodeUUID, encryptedFileStructWithHMAC)

		return nil
	}
	if ok == false { // if the file has never existed OR you are not the owner of the file
		// -------------------- CHECK IF THE INVITE EXISTS --------------------
		inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "invite"))[:16])
		if err != nil {
			return errors.New("error: hashing the UUID failed - 818")
		}
		_, ok := userlib.DatastoreGet(inviteUUID) // gives you the invite struct
		if ok == false { // IF THE FILE HAS NEVER EXISTED BEFORE (you are the fileowner)
			// -------------------- CREATE THE INTERMEDIATE STRUCT AND STORE IT IN DATASTORE --------------------
			var intermediateStruct Intermediate
			linkedListStorageKey := uuid.New()
			intermediateStruct.NextPTR = linkedListStorageKey
			intermediateRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
			intermediateStruct.PrivateKey = intermediateRootKey

			privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateRootKey, []byte("privateKey")) // PURPOSE: filename/username
			if err != nil {
				return errors.New("error: hmac creation failed")
			}

			// MARSHALL THE INTERMEDIATE STRUCT
			marshalledIntermediateStruct, err := json.Marshal(intermediateStruct)
			if err != nil {
				return errors.New("error: marshal failed")
			}

			// ENCRYPT THE INTERMEDIATE STRUCT
			encryptedIntermediateStruct := userlib.SymEnc(privateKeyForIntermediateStruct[:16], userlib.RandomBytes(16), marshalledIntermediateStruct)
			// "ENCRYPT THEN MAC" approach - mac over the ciphertext
			privateKeyForIntermediateStructHMAC, err := userlib.HashKDF(intermediateRootKey, []byte("HMAC")) // PURPOSE: filename-username
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			HMACforIntermediateStruct, err := userlib.HMACEval(privateKeyForIntermediateStructHMAC[:16], encryptedIntermediateStruct)
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
			encryptedIntermediateStructWithHMAC := append(encryptedIntermediateStruct, HMACforIntermediateStruct...)

			// SET - add the "filename/username" to the datastore alongside the struct
			storageKeyForIntermediateStruct, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
			if err != nil {
				return err
			}

			// SET - key: filename/username, value: encrypted intermediate
			userlib.DatastoreSet(storageKeyForIntermediateStruct, encryptedIntermediateStructWithHMAC)

			// -------------------- CREATE THE LINKEDLIST STRUCT AND STORE IT IN DATASTORE --------------------
			var fileLinkedList FileLinkedList
			firstNodeUUID := uuid.New()
			fileLinkedList.FirstPTR = firstNodeUUID // set this to the first file node
			nextNodeUUID := uuid.New()
			fileLinkedList.LastPTR = nextNodeUUID // set the last pointer to the nextNode (location in memory)

			linkedListRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
			privateKeyForLinkedListStruct, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL")) // PURPOSE: filename/username
			if err != nil {
				return errors.New("error: hmac creation failed")
			}

			// MARSHALL THE FILE LINKED LIST STRUCT
			marshalledLinkedListStruct, err := json.Marshal(fileLinkedList)
			if err != nil {
				return errors.New("error: marshal failed")
			}

			// ENCRYPT THE FILE LINKED LIST STRUCT
			encryptedLinkedListStruct := userlib.SymEnc(privateKeyForLinkedListStruct[:16], userlib.RandomBytes(16), marshalledLinkedListStruct)
			// "ENCRYPT THEN MAC" approach - mac over the ciphertext
			privateKeyForLinkedListHMAC, err := userlib.HashKDF(linkedListRootKey, []byte("HMACforLL")) // PURPOSE: filename-username
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			HMACforLinkedList, err := userlib.HMACEval(privateKeyForLinkedListHMAC[:16], encryptedLinkedListStruct)
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
			encryptedLinkedListStructWithHMAC := append(encryptedLinkedListStruct, HMACforLinkedList...)

			// SET - key: random UUID, value: linkedlist
			userlib.DatastoreSet(linkedListStorageKey, encryptedLinkedListStructWithHMAC)

			// ----------------------------------------- CREATE THE FILE NODE STRUCT ---------------------------------------------------
			var fileNode FileDataNode
			fileNode.Filename = filename
			fileNode.FileData = content
			fileNode.NextPTR = nextNodeUUID // the next node of the file node = next node of the file linked list

			fileNodeRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
			privateKeyForFileNodeStruct, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode")) // PURPOSE: username/filename
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// MARSHALL THE FILE NODE STRUCT
			marshalledFileStruct, err := json.Marshal(fileNode)
			if err != nil {
				return errors.New("error: marshal failed")
			}
			// ENCRYPT THE FILE NODE STRUCT
			encryptedFileStruct := userlib.SymEnc(privateKeyForFileNodeStruct[:16], userlib.RandomBytes(16), marshalledFileStruct)
			// "ENCRYPT THEN MAC" approach - mac over the ciphertext
			privateKeyForFileNodeHMAC, err := userlib.HashKDF(fileNodeRootKey, []byte("HMACforFileNode")) // PURPOSE: username-filename
			HMAC, err := userlib.HMACEval(privateKeyForFileNodeHMAC[:16], encryptedFileStruct)
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
			encryptedFileStructWithHMAC := append(encryptedFileStruct, HMAC...)

			// SET - place this key (file node): key = firstNode location
			userlib.DatastoreSet(firstNodeUUID, encryptedFileStructWithHMAC)

			return nil
		}
		// IF YOU ARE NOT THE FILEOWNER, but want to overwrite the file
		if ok == true { 
			// ------------------------------------ DECRYPT THE INVITE STRUCT ------------------------------------
			encryptedInviteFileWithDS, ok := userlib.DatastoreGet(inviteUUID) // gives you the invite struct
			if ok == false {
				return errors.New("error: hashing the UUID failed - 822/4")
			}

			// CHECK DIGITAL SIGNATURE
			extractEncryptedInviteStruct := encryptedInviteFileWithDS[0 : len(encryptedInviteFileWithDS)-256] // DSs are 256 bytes long!
			extractDS := encryptedInviteFileWithDS[len(encryptedInviteFileWithDS)-256 : len(encryptedInviteFileWithDS)]
			// GET THE SENDERUSERNAME'S PUBLIC KEY for rsa
			senderUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "sender"))[:16]) // get the sender username
			if err != nil {
				return errors.New("error: hashing the UUID failed - 818")
			}
			senderName, ok := userlib.DatastoreGet(senderUUID) // gives you the sender name
			// UNMARSHALL THE SENDER NAME
			var senderNameString string
			err = json.Unmarshal(senderName, &senderNameString)
			if err != nil {
				return errors.New("error: unmarshal failed")
			}
			senderPublicKey, ok := userlib.KeystoreGet(senderNameString + "signKey")
			if ok == false {
				return errors.New("authenticating DS did not work 1-1")
			}
			err = userlib.DSVerify(senderPublicKey, extractEncryptedInviteStruct, extractDS)
			if err != nil {
				return errors.New("authenticating DS did not work 1-2")
			}
			// DECRYPT THE INVITE STRUCT
			decryptedInviteStruct, err := userlib.PKEDec(userdata.PrivateKeyGen, extractEncryptedInviteStruct)
			if err != nil {
				return errors.New("authenticating DS did not work 2")
			}
			// UNMARSHALL THE INVITE STRUCT
			var userInviteStruct Invitation
			err = json.Unmarshal(decryptedInviteStruct, &userInviteStruct)
			if err != nil {
				return errors.New("error: unmarshal failed")
			}
			// RETRIEVE THE ARGON2KEY
			intermediateArgon2Key := userInviteStruct.PrivateKey
			intermediateUUID = userInviteStruct.NextPTR	

			//------------------------------------ SYMMETRICALLY DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
			encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID)
			if ok == false { 
				return errors.New("error: hmac creation failed 611")
			}
			// CHECK HMACS: authenticity/integrity check
			extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
			intermediateHMACRootKey := intermediateArgon2Key                                                                       // key to symmetrically DECRYPT the intermediate
			// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
			privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
			if err != nil {
				return errors.New("error: hmac creation failed 611")
			}
			tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
			if err != nil {
				return errors.New("error: hmac failed 2")
			}
			// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
			extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
			authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
			if authenticateHMAC == false {
				return errors.New("user struct was tampered with: line 844-2")
			}
			privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
			if err != nil {
				return errors.New("user struct was tampered with: 849")
			}
			// DECRYPT THE INTERMEDIATE STRUCT
			decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
			// UNMARSHALL THE INTERMEDIATE STRUCT
			var userIntermediateStruct Intermediate
			err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
			if err != nil {
				return errors.New("error: unmarshal failed: 859")
			}
			linkedListLocation := userIntermediateStruct.NextPTR      // this points to "Alice's" LL file struct
			intermediateArgon2Key = userIntermediateStruct.PrivateKey // argon2key

			// -------------------- TRY TO DECRYPT THE LL - if you can, you are NOT a revoked user and can proceed ------------------
			encryptedLinkedListStructWithHMAC, ok := userlib.DatastoreGet(linkedListLocation)
			// ERROR CHECK #1: The given filename does not exist in the personal file namespace of the caller.
			if ok == false {
				return errors.New("cannot access the linked list")
			}
			// IF YOU CAN find the LL, that means it was NOT deleted -> this user was NOT revoked

			// -------------------- CREATE THE LINKEDLIST STRUCT AND STORE IT IN DATASTORE to override the original file --------------------
			var fileLinkedList FileLinkedList
			firstNodeUUID := uuid.New()
			fileLinkedList.FirstPTR = firstNodeUUID // set this to the first file node
			nextNodeUUID := uuid.New()
			fileLinkedList.LastPTR = nextNodeUUID // set the last pointer to the nextNode (location in memory)

			linkedListRootKey := intermediateArgon2Key
			privateKeyForLinkedListStruct, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL")) // PURPOSE: filename/username
			if err != nil {
				return errors.New("error: hmac creation failed")
			}

			// MARSHALL THE FILE LINKED LIST STRUCT
			marshalledLinkedListStruct, err := json.Marshal(fileLinkedList)
			if err != nil {
				return errors.New("error: marshal failed")
			}

			// ENCRYPT THE FILE LINKED LIST STRUCT
			encryptedLinkedListStruct := userlib.SymEnc(privateKeyForLinkedListStruct[:16], userlib.RandomBytes(16), marshalledLinkedListStruct)
			// "ENCRYPT THEN MAC" approach - mac over the ciphertext
			privateKeyForLinkedListHMAC, err := userlib.HashKDF(linkedListRootKey, []byte("HMACforLL")) // PURPOSE: filename-username
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			HMACforLinkedList, err := userlib.HMACEval(privateKeyForLinkedListHMAC[:16], encryptedLinkedListStruct)
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
			encryptedLinkedListStructWithHMAC = append(encryptedLinkedListStruct, HMACforLinkedList...)

			// SET - key: random UUID, value: linkedlist
			userlib.DatastoreSet(linkedListLocation, encryptedLinkedListStructWithHMAC)

			// ----------------------------------------- CREATE THE FILE NODE STRUCT ---------------------------------------------------
			var fileNode FileDataNode
			fileNode.Filename = filename
			fileNode.FileData = content
			fileNode.NextPTR = nextNodeUUID // the next node of the file node = next node of the file linked list

			fileNodeRootKey := intermediateArgon2Key
			privateKeyForFileNodeStruct, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode")) // PURPOSE: username/filename
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// MARSHALL THE FILE NODE STRUCT
			marshalledFileStruct, err := json.Marshal(fileNode)
			if err != nil {
				return errors.New("error: marshal failed")
			}
			// ENCRYPT THE FILE NODE STRUCT
			encryptedFileStruct := userlib.SymEnc(privateKeyForFileNodeStruct[:16], userlib.RandomBytes(16), marshalledFileStruct)
			// "ENCRYPT THEN MAC" approach - mac over the ciphertext
			privateKeyForFileNodeHMAC, err := userlib.HashKDF(fileNodeRootKey, []byte("HMACforFileNode")) // PURPOSE: username-filename
			HMAC, err := userlib.HMACEval(privateKeyForFileNodeHMAC[:16], encryptedFileStruct)
			if err != nil {
				return errors.New("error: hmac creation failed")
			}
			// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
			encryptedFileStructWithHMAC := append(encryptedFileStruct, HMAC...)

			// SET - place this key (file node): key = firstNode location
			userlib.DatastoreSet(firstNodeUUID, encryptedFileStructWithHMAC)
			return nil
		}
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// STEPS:
	// 1) Unmarshal the intermediate struct
	// MAKE SURE THe UUID OF DATASTORE IS CORRECT
	// 1) update the file linked list last ptr to a new uuid (location)
	// 2) create a new file node and have its next ptr point to the same new uuid that the linked list's last ptr is pointing to now
	// 3) add the file node to the data store (key: old uuid of the previous file node above it/of the linked list's last ptr before we updated it)

	// ------------------------------------ FILE OWNER CHECK ------------------------------------
	intermediateUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return errors.New("error: hashing the UUID failed - 828")
	}
	encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID) // gives you the intermediate struct
	if ok == true { // iF YOU ARE THE FILE OWNER
		// ---------------------------- UNRAVEL THE INTERMEDIATE TO ACCESS THE LINKED LIST ----------------------------
		// CHECK HMACS: authenticity/integrity check
		extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
		intermediateHMACRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
		if err != nil {
			return errors.New("error: hmac creation failed 416")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
		if err != nil {
			return errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]

		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return errors.New("user struct was tampered with - line 415")
		}

		privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
		if err != nil {
			return err
		}
		// DECRYPT THE INTERMEDIATE STRUCT
		decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
		// UNMARSHALL THE INTERMEDIATE STRUCT
		var userIntermediateStruct Intermediate
		err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
		if err != nil {
			return errors.New("error: unmarshal failed")
		}
		linkedListLocation := userIntermediateStruct.NextPTR
		privateKey := userIntermediateStruct.PrivateKey

		// ----------------------------------- LINKED LIST -------------------------------------------
		// RETRIEVE THE LAST PTR for the file linked list
		storageKey := linkedListLocation
		encryptedLinkedListStructWithHMAC, ok := userlib.DatastoreGet(storageKey)
		// ERROR CHECK #1: The given filename does not exist in the personal file namespace of the caller.
		if !ok {
			return errors.New(strings.ToTitle("file not found - 1"))
		}

		// CHECK HMACS: authenticity/integrity check
		// EXTRACT THE LINKED LIST STRUCT - splice to get the user struct
		extractEncryptedLinkedList := encryptedLinkedListStructWithHMAC[0 : len(encryptedLinkedListStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
		linkedListHMACRootKey := privateKey
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err = userlib.HashKDF(linkedListHMACRootKey, []byte("HMACforLL"))
		if err != nil {
			return errors.New("error: hmac creation failed 461")
		}
		tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedLinkedList)
		if err != nil {
			return errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC = encryptedLinkedListStructWithHMAC[len(encryptedLinkedListStructWithHMAC)-64 : len(encryptedLinkedListStructWithHMAC)]
		authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return errors.New("user struct was tampered with - line 465")
		}
		privateKeyForLinkedListStruct, err := userlib.HashKDF(linkedListHMACRootKey, []byte("privateKeyforLL")) // PURPOSE: filename/username
		if err != nil {
			return err
		}
		// DECRYPT THE LINKED LIST STRUCT
		decryptedLinkedListStruct := userlib.SymDec(privateKeyForLinkedListStruct[:16], extractEncryptedLinkedList) // decrypt the user struct with the given user key

		// UNMARSHALL THE LINKED LIST STRUCT
		var userLinkedList FileLinkedList
		err = json.Unmarshal(decryptedLinkedListStruct, &userLinkedList)
		if err != nil {
			return errors.New("error: unmarshal failed")
		}
		// SAVE THE LAST PTR FOR THE LINKED LIST STRUCT
		oldLastPtr := userLinkedList.LastPTR // the one we want to store in datastore when we add a filenode
		newUUID := uuid.New()
		// UPDATE THE LAST POINTER to a new uuid - this is the new file node's next ptr
		userLinkedList.LastPTR = newUUID

		// ------------------------  ENCRYPT + MARSHALL + HMAC THE LINKED LIST STRUCT ------------------------
		linkedListRootKey := privateKey
		privateKeyForLinkedList, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL"))
		if err != nil {
			return errors.New("error: private key creation failed 2")
		}
		marshalledLinkedListStruct, err := json.Marshal(userLinkedList)
		if err != nil {
			return errors.New("error: marshal failed")
		}
		encryptedLinkedListStruct := userlib.SymEnc(privateKeyForLinkedList[:16], userlib.RandomBytes(16), marshalledLinkedListStruct)
		privateKeyForLinkedListHMAC, err := userlib.HashKDF(linkedListRootKey, []byte("HMACforLL")) // CHANGE THE PURPOSE HERE
		if err != nil {
			return errors.New("error: hmac creation failed 3")
		}
		HMACforLinkedList, err := userlib.HMACEval(privateKeyForLinkedListHMAC[:16], encryptedLinkedListStruct)
		if err != nil {
			return errors.New("error: hmac creation failed 4")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedLinkedListStructWithHMAC = append(encryptedLinkedListStruct, HMACforLinkedList...)

		// SET THE LINKED LIST STRUCT
		userlib.DatastoreSet(linkedListLocation, encryptedLinkedListStructWithHMAC)

		// ------------------------  CREATE FILENODE + ENCRYPT + MARSHALL + HMAC THE LINKED LIST STRUCT ------------------------
		var fileNode FileDataNode
		fileNode.Filename = filename
		fileNode.FileData = content // here, we appended the CONTENT
		fileNode.NextPTR = newUUID  // file node's next should be the SAME as the linked list's last ptr

		fileNodeRootKey := privateKey
		privateKeyForFileNode, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode"))
		if err != nil {
			return errors.New("error: private key creation failed 2")
		}

		// MARSHALL THE FILE NODE STRUCT
		marshalledFileNodeStruct, err := json.Marshal(fileNode)
		if err != nil {
			return errors.New("error: marshal failed")
		}

		// ENCRYPT THE FILE NODE STRUCT
		encryptedFileNodeStruct := userlib.SymEnc(privateKeyForFileNode[:16], userlib.RandomBytes(16), marshalledFileNodeStruct)
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		privateKeyForFileNodeHMAC, err := userlib.HashKDF(fileNodeRootKey, []byte("HMACforFileNode")) // CHANGE THE PURPOSE HERE
		if err != nil {
			return errors.New("error: hmac creation failed 3")
		}
		HMACforFileNode, err := userlib.HMACEval(privateKeyForFileNodeHMAC[:16], encryptedFileNodeStruct)
		if err != nil {
			return errors.New("error: hmac creation failed 4")
		}

		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedFileNodeStructWithHMAC := append(encryptedFileNodeStruct, HMACforFileNode...)

		// SET - place this key (random uuid as key and value to be the new file node we added)
		userlib.DatastoreSet(oldLastPtr, encryptedFileNodeStructWithHMAC)
		return nil
	}
	// IF YOU ARE NOT THE FILEOWNER
	// ------------------------------------ GET THE INVITE STRUCT ------------------------------------
	inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "invite"))[:16])
	if err != nil {
		return errors.New("error: hashing the UUID failed - 818")
	}
	// ------------------------------------ DECRYPT THE INVITE STRUCT ------------------------------------
	encryptedInviteFileWithDS, ok := userlib.DatastoreGet(inviteUUID) // gives you the invite struct
	if ok == false {
		return errors.New("error: hashing the UUID failed - 822-1")
	}
	// CHECK DIGITAL SIGNATURE
	extractEncryptedInviteStruct := encryptedInviteFileWithDS[0 : len(encryptedInviteFileWithDS)-256] // DSs are 256 bytes long!
	extractDS := encryptedInviteFileWithDS[len(encryptedInviteFileWithDS)-256 : len(encryptedInviteFileWithDS)]
	// GET THE SENDERUSERNAME'S PUBLIC KEY for rsa
	senderUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "sender"))[:16]) // get the sender username
	if err != nil {
		return errors.New("error: hashing the UUID failed - 818")
	}
	senderName, ok := userlib.DatastoreGet(senderUUID) // gives you the sender name
	// UNMARSHALL THE SENDER NAME
	var senderNameString string
	err = json.Unmarshal(senderName, &senderNameString)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}
	senderPublicKey, ok := userlib.KeystoreGet(senderNameString + "signKey")
	if ok == false {
		return errors.New("authenticating DS did not work 1-3")
	}
	err = userlib.DSVerify(senderPublicKey, extractEncryptedInviteStruct, extractDS)
	if err != nil {
		return errors.New("authenticating DS did not work 1-4")
	}
	// DECRYPT THE INVITE STRUCT
	decryptedInviteStruct, err := userlib.PKEDec(userdata.PrivateKeyGen, extractEncryptedInviteStruct)
	if err != nil {
		return errors.New("authenticating DS did not work 2")
	}
	// UNMARSHALL THE INVITE STRUCT
	var userInviteStruct Invitation
	err = json.Unmarshal(decryptedInviteStruct, &userInviteStruct)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}
	// RETRIEVE THE ARGON2KEY
	intermediateArgon2Key := userInviteStruct.PrivateKey
	intermediateUUID = userInviteStruct.NextPTR

	//------------------------------------ SYMMETRICALLY DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
	encryptedIntermediateFileWithHMAC, ok = userlib.DatastoreGet(intermediateUUID)
	// CHECK HMACS: authenticity/integrity check
	extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
	intermediateHMACRootKey := intermediateArgon2Key                                                                       // key to symmetrically DECRYPT the intermediate
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
	if err != nil {
		return errors.New("error: hmac creation failed 611")
	}
	tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
	if err != nil {
		return errors.New("error: hmac failed 2")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
	authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return errors.New("user struct was tampered with: line 844-2-2")
	}
	privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
	if err != nil {
		return errors.New("user struct was tampered with: 849")
	}
	// DECRYPT THE INTERMEDIATE STRUCT
	decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE INTERMEDIATE STRUCT
	var userIntermediateStruct Intermediate
	err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
	if err != nil {
		return errors.New("error: unmarshal failed: 859")
	}
	linkedListLocation := userIntermediateStruct.NextPTR      // this points to "Alice's" LL file struct
	intermediateArgon2Key = userIntermediateStruct.PrivateKey // argon2key

	// --------------------------- EXTRACT THE LINKED LIST STRUCT - splice to get the user struct ---------------------------
	// EXTRACT THE "FILENAME/USERNAME" key from the datastore
	encryptedLinkedListStructWithHMAC, ok := userlib.DatastoreGet(linkedListLocation)
	// ERROR CHECK #1: The given filename does not exist in the personal file namespace of the caller.
	if !ok {
		return errors.New(strings.ToTitle("file not found - 643"))
	}
	// CHECK HMACS - make sure hmac is not invalid
	extractEncryptedLinkedList := encryptedLinkedListStructWithHMAC[0 : len(encryptedLinkedListStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
	linkedListHMACRootKey := intermediateArgon2Key                                                                 // to symmetrically DECRYPT the LL file
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err = userlib.HashKDF(linkedListHMACRootKey, []byte("HMACforLL"))
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedLinkedList)
	if err != nil {
		return errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC = encryptedLinkedListStructWithHMAC[len(encryptedLinkedListStructWithHMAC)-64 : len(encryptedLinkedListStructWithHMAC)]
	authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return errors.New("user struct was tampered- line 644")
	}
	linkedListRootKey := intermediateArgon2Key
	privateKeyForLinkedList, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL"))
	if err != nil {
		return errors.New("error: hmac creation failed- line 650")
	}
	// DECRYPT THE FILE LINKED LIST STRUCT
	decryptedLinkedListStruct := userlib.SymDec(privateKeyForLinkedList[:16], extractEncryptedLinkedList) // decrypt the struct
	// UNMARSHALL THE FILE LINKED LIST STRUCT
	var userLinkedList FileLinkedList
	userFilePtr := &userLinkedList
	err = json.Unmarshal(decryptedLinkedListStruct, userFilePtr)
	if err != nil {
		return errors.New("error: unmarshall failed 1")
	}
	// SAVE THE LAST PTR FOR THE LINKED LIST STRUCT
	oldLastPtr := userLinkedList.LastPTR // the one we want to store in datastore when we add a filenode
	newUUID := uuid.New()
	// UPDATE THE LAST POINTER to a new uuid - this is the new file node's next ptr
	userLinkedList.LastPTR = newUUID

	// ------------------------  ENCRYPT + MARSHALL + HMAC THE LINKED LIST STRUCT ------------------------
	linkedListRootKey = intermediateArgon2Key
	privateKeyForLinkedList, err = userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL"))
	if err != nil {
		return errors.New("error: private key creation failed 2")
	}
	marshalledLinkedListStruct, err := json.Marshal(userLinkedList)
	if err != nil {
		return errors.New("error: marshal failed")
	}
	encryptedLinkedListStruct := userlib.SymEnc(privateKeyForLinkedList[:16], userlib.RandomBytes(16), marshalledLinkedListStruct)
	privateKeyForLinkedListHMAC, err := userlib.HashKDF(linkedListRootKey, []byte("HMACforLL")) // CHANGE THE PURPOSE HERE
	if err != nil {
		return errors.New("error: hmac creation failed 3")
	}
	HMACforLinkedList, err := userlib.HMACEval(privateKeyForLinkedListHMAC[:16], encryptedLinkedListStruct)
	if err != nil {
		return errors.New("error: hmac creation failed 4")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedLinkedListStructWithHMAC = append(encryptedLinkedListStruct, HMACforLinkedList...)

	// SET THE LINKED LIST STRUCT
	userlib.DatastoreSet(linkedListLocation, encryptedLinkedListStructWithHMAC)

	// ------------------------  CREATE FILENODE + ENCRYPT + MARSHALL + HMAC THE LINKED LIST STRUCT ------------------------
	var fileNode FileDataNode
	fileNode.Filename = filename
	fileNode.FileData = content // here, we appended the CONTENT
	fileNode.NextPTR = newUUID  // file node's next should be the SAME as the linked list's last ptr

	fileNodeRootKey := intermediateArgon2Key
	privateKeyForFileNode, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode"))
	if err != nil {
		return errors.New("error: private key creation failed 2")
	}
	// MARSHALL THE FILE NODE STRUCT
	marshalledFileNodeStruct, err := json.Marshal(fileNode)
	if err != nil {
		return errors.New("error: marshal failed")
	}
	// ENCRYPT THE FILE NODE STRUCT
	encryptedFileNodeStruct := userlib.SymEnc(privateKeyForFileNode[:16], userlib.RandomBytes(16), marshalledFileNodeStruct)
	// "ENCRYPT THEN MAC" approach - mac over the ciphertext
	privateKeyForFileNodeHMAC, err := userlib.HashKDF(fileNodeRootKey, []byte("HMACforFileNode")) // CHANGE THE PURPOSE HERE
	if err != nil {
		return errors.New("error: hmac creation failed 3")
	}
	HMACforFileNode, err := userlib.HMACEval(privateKeyForFileNodeHMAC[:16], encryptedFileNodeStruct)
	if err != nil {
		return errors.New("error: hmac creation failed 4")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedFileNodeStructWithHMAC := append(encryptedFileNodeStruct, HMACforFileNode...)

	// SET - place this key (random uuid as key and value to be the new file node we added)
	userlib.DatastoreSet(oldLastPtr, encryptedFileNodeStructWithHMAC)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// STEPS:
	// 1) unravel the intermediate struct to gain access to the linked list file struct
	// 2) get the linked list's first ptr to the first file node
	// 3) traverse over every file node UNTIL the file node does not exist in data store (that means we have hit the end of the linked list)
	// 4) during each iteration, append the content of the file node to the running content variable (fileContent here)
	// 5) return this running variable of the content

	// ------------------------------------ FILE OWNER CHECK ------------------------------------
	intermediateUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return nil, errors.New("error: hashing the UUID failed - 828")
	}
	_, ok := userlib.DatastoreGet(intermediateUUID) // gives you the intermediate struct
	if ok == true { // iF YOU ARE THE FILE OWNER
		// ----------------------------- DECRYPT INTERMEDIATE STRUCT - to get the linked list uuid ------------------------
		intermediateUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
		if err != nil {
			return nil, errors.New("error")
		}
		encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID)
		if ok == false {
			return nil, errors.New("error")
		}
		// CHECK HMACS: authenticity/integrity check
		extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
		intermediateHMACRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
		if err != nil {
			return nil, errors.New("error: hmac creation failed 774")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
		if err != nil {
			return nil, errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return nil, errors.New("user struct was tampered with - line 596")
		}
		privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
		if err != nil {
			return nil, errors.New("user struct was tampered with - line 601")
		}
		// DECRYPT THE INTERMEDIATE STRUCT
		decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
		// UNMARSHALL THE INTERMEDIATE STRUCT
		var userIntermediateStruct Intermediate
		err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
		if err != nil {
			return nil, errors.New("error: unmarshal failed")
		}
		linkedListLocation := userIntermediateStruct.NextPTR
		updatedKey := userIntermediateStruct.PrivateKey

		var fileContent []byte
		// EXTRACT THE "FILENAME/USERNAME" key from the datastore
		encryptedLinkedListStructWithHMAC, ok := userlib.DatastoreGet(linkedListLocation)
		// ERROR CHECK #1: The given filename does not exist in the personal file namespace of the caller.
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found - 806"))
		}
		// --------------------------- EXTRACT THE LINKED LIST STRUCT - splice to get the user struct ---------------------------
		// CHECK HMACS - make sure hmac is not invalid
		extractEncryptedLinkedList := encryptedLinkedListStructWithHMAC[0 : len(encryptedLinkedListStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
		linkedListHMACRootKey := updatedKey
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err = userlib.HashKDF(linkedListHMACRootKey, []byte("HMACforLL"))
		if err != nil {
			return nil, errors.New("error: hmac creation failed")
		}
		tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedLinkedList)
		if err != nil {
			return nil, errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC = encryptedLinkedListStructWithHMAC[len(encryptedLinkedListStructWithHMAC)-64 : len(encryptedLinkedListStructWithHMAC)]
		authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return nil, errors.New("user struct was tampered- line 644")
		}
		linkedListRootKey := updatedKey // create the source key
		privateKeyForLinkedList, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL"))
		if err != nil {
			return nil, errors.New("error: hmac creation failed- line 650")
		}
		// DECRYPT THE FILE LINKED LIST STRUCT
		decryptedLinkedListStruct := userlib.SymDec(privateKeyForLinkedList[:16], extractEncryptedLinkedList) // decrypt the struct
		// UNMARSHALL THE FILE LINKED LIST STRUCT
		var userFile FileLinkedList
		userFilePtr := &userFile
		err = json.Unmarshal(decryptedLinkedListStruct, userFilePtr)
		if err != nil {
			return nil, errors.New("error: unmarshall failed 1")
		}
		firstNodeFirstPTR := userFile.FirstPTR // GET THE FIRST NODE'S LOCATION

		encryptedFileNodeStructWithHMAC, ok := userlib.DatastoreGet(firstNodeFirstPTR) // GET THE FIRST NODE STRUCT ITSELF
		if !ok {
			return nil, errors.New(strings.ToTitle("file not found - 845"))
		}

		for ok == true { // if the UUID does exist - the file node does exist
			// ------------- DECRYPTING THE FILE NODES -------------
			// CHECK HMACS - make sure hmac is not invalid
			extractEncryptedFileNode := encryptedFileNodeStructWithHMAC[0 : len(encryptedFileNodeStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
			fileNodeHMACRootKey := linkedListRootKey

			// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
			privateKeyForTempHMAC, err := userlib.HashKDF(fileNodeHMACRootKey, []byte("HMACforFileNode"))
			if err != nil {
				return nil, errors.New("error: hmac creation failed")
			}
			tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedFileNode)
			if err != nil {
				return nil, errors.New("error: hmac failed")
			}
			// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
			extractHMAC := encryptedFileNodeStructWithHMAC[len(encryptedFileNodeStructWithHMAC)-64 : len(encryptedFileNodeStructWithHMAC)]

			authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
			if authenticateHMAC == false {
				return nil, errors.New("user struct was tampered with - line 691")
			}

			// CREATE THE ARGON2KEY for the file node
			fileNodeRootKey := linkedListRootKey
			privateKeyForFileNode, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode"))
			if err != nil {
				return nil, errors.New("error: hmac creation failed - line 698")
			}

			// DECRYPT THE FILE NODE STRUCT
			decryptedFileNodeStruct := userlib.SymDec(privateKeyForFileNode[:16], extractEncryptedFileNode) // decrypt the file node struct

			// UNMARSHALL THE FILE NODE STRUCT
			var userFileNode FileDataNode
			userFileNodeptr := &userFileNode
			err = json.Unmarshal(decryptedFileNodeStruct, userFileNodeptr)
			if err != nil {
				return nil, errors.New("error: unmarshall failed 2")
			}

			// APPEND THE CONTENT TO THE RUNNING VARIABLE
			fileContent = append(fileContent, userFileNode.FileData...)

			// RESET THE FILE NODE STRUCT TO GET THE NEXT FILE NODE IN THE LINKED LIST
			encryptedFileNodeStructWithHMAC, ok = userlib.DatastoreGet(userFileNode.NextPTR)
		}
		return fileContent, nil
	}
	// YOU ARE NOT THE OWNER
	// ------------------------------------ GET THE INVITE STRUCT ------------------------------------
	inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "invite"))[:16])
	if err != nil {
		return nil, errors.New("error: hashing the UUID failed - 818")
	}
	// ------------------------------------ DECRYPT THE INVITE STRUCT ------------------------------------
	encryptedInviteFileWithDS, ok := userlib.DatastoreGet(inviteUUID) // gives you the invite struct
	if ok == false {
		return nil, errors.New("error: hashing the UUID failed - 822-2")
	}
	// CHECK DIGITAL SIGNATURE
	extractEncryptedInviteStruct := encryptedInviteFileWithDS[0 : len(encryptedInviteFileWithDS)-256] // DSs are 256 bytes long!
	extractDS := encryptedInviteFileWithDS[len(encryptedInviteFileWithDS)-256 : len(encryptedInviteFileWithDS)]
	// GET THE SENDERUSERNAME'S PUBLIC KEY for rsa
	senderUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "sender"))[:16]) // get the sender username
	if err != nil {
		return nil, errors.New("error: hashing the UUID failed - 818")
	}
	senderName, ok := userlib.DatastoreGet(senderUUID) // gives you the sender name
	// UNMARSHALL THE SENDER NAME
	var senderNameString string
	err = json.Unmarshal(senderName, &senderNameString)
	if err != nil {
		return nil, errors.New("error: unmarshal failed")
	}
	senderPublicKey, ok := userlib.KeystoreGet(senderNameString + "signKey")
	if ok == false {
		return nil, errors.New("authenticating DS did not work 1-5")
	}
	err = userlib.DSVerify(senderPublicKey, extractEncryptedInviteStruct, extractDS)
	if err != nil {
		return nil, errors.New("authenticating DS did not work 1-6")
	}
	// DECRYPT THE INVITE STRUCT
	decryptedInviteStruct, err := userlib.PKEDec(userdata.PrivateKeyGen, extractEncryptedInviteStruct)
	if err != nil {
		return nil, errors.New("authenticating DS did not work 2")
	}
	// UNMARSHALL THE INVITE STRUCT
	var userInviteStruct Invitation
	err = json.Unmarshal(decryptedInviteStruct, &userInviteStruct)
	if err != nil {
		return nil, errors.New("error: unmarshal failed")
	}
	// RETRIEVE THE ARGON2KEY
	inviteArgon2Key := userInviteStruct.PrivateKey
	intermediateUUID = userInviteStruct.NextPTR

	//------------------------------------ SYMMETRICALLY DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
	encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID)
	// CHECK HMACS: authenticity/integrity check
	extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
	intermediateHMACRootKey := inviteArgon2Key                                                                             // key to symmetrically DECRYPT the intermediate
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
	if err != nil {
		return nil, errors.New("error: hmac creation failed 956")
	}
	tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
	if err != nil {
		return nil, errors.New("error: hmac failed 2")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC) - 64: len(encryptedIntermediateFileWithHMAC)]
	authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return nil, errors.New("user struct was tampered with: line 844-3")
	}
	privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
	if err != nil {
		return nil, errors.New("user struct was tampered with: 849")
	}
	// DECRYPT THE INTERMEDIATE STRUCT
	decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE INTERMEDIATE STRUCT
	var userIntermediateStruct Intermediate
	err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
	if err != nil {
		return nil, errors.New("error: unmarshal failed: 859")
	}
	linkedListLocation := userIntermediateStruct.NextPTR       // this points to "Alice's" LL file struct
	intermediateArgon2Key := userIntermediateStruct.PrivateKey // argon2key

	// --------------------------- EXTRACT THE LINKED LIST STRUCT - splice to get the user struct ---------------------------
	var fileContent []byte
	// EXTRACT THE "FILENAME/USERNAME" key from the datastore
	encryptedLinkedListStructWithHMAC, ok := userlib.DatastoreGet(linkedListLocation)
	// ERROR CHECK #1: The given filename does not exist in the personal file namespace of the caller.
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found - 986"))
	}
	// CHECK HMACS - make sure hmac is not invalid
	extractEncryptedLinkedList := encryptedLinkedListStructWithHMAC[0 : len(encryptedLinkedListStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
	linkedListHMACRootKey := intermediateArgon2Key                                                                 // to symmetrically DECRYPT the LL file
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err = userlib.HashKDF(linkedListHMACRootKey, []byte("HMACforLL"))
	if err != nil {
		return nil, errors.New("error: hmac creation failed")
	}
	tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedLinkedList)
	if err != nil {
		return nil, errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC = encryptedLinkedListStructWithHMAC[len(encryptedLinkedListStructWithHMAC)-64 : len(encryptedLinkedListStructWithHMAC)]
	authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return nil, errors.New("user struct was tampered- line 644")
	}
	linkedListRootKey := intermediateArgon2Key
	privateKeyForLinkedList, err := userlib.HashKDF(linkedListRootKey, []byte("privateKeyforLL"))
	if err != nil {
		return nil, errors.New("error: hmac creation failed- line 650")
	}
	// DECRYPT THE FILE LINKED LIST STRUCT
	decryptedLinkedListStruct := userlib.SymDec(privateKeyForLinkedList[:16], extractEncryptedLinkedList) // decrypt the struct
	// UNMARSHALL THE FILE LINKED LIST STRUCT
	var userFile FileLinkedList
	userFilePtr := &userFile
	err = json.Unmarshal(decryptedLinkedListStruct, userFilePtr)
	if err != nil {
		return nil, errors.New("error: unmarshall failed 1")
	}
	firstNodeFirstPTR := userFile.FirstPTR // GET THE FIRST NODE'S LOCATION
	encryptedFileNodeStructWithHMAC, ok := userlib.DatastoreGet(firstNodeFirstPTR) // GET THE FIRST NODE STRUCT ITSELF
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found - 1023"))
	}

	// ------------------------- LOAD --------------------------
	for ok == true { // if the UUID does exist - the file node does exist
		// CHECK HMACS - make sure hmac is not invalid
		extractEncryptedFileNode := encryptedFileNodeStructWithHMAC[0 : len(encryptedFileNodeStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
		fileNodeHMACRootKey := intermediateArgon2Key

		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(fileNodeHMACRootKey, []byte("HMACforFileNode"))
		if err != nil {
			return nil, errors.New("error: hmac creation failed")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedFileNode)
		if err != nil {
			return nil, errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedFileNodeStructWithHMAC[len(encryptedFileNodeStructWithHMAC)-64 : len(encryptedFileNodeStructWithHMAC)]

		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return nil, errors.New("user struct was tampered with - line 691")
		}

		// CREATE THE ARGON2KEY for the file node
		fileNodeRootKey := intermediateArgon2Key
		privateKeyForFileNode, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode"))
		if err != nil {
			return nil, errors.New("error: hmac creation failed - line 698")
		}

		// DECRYPT THE FILE NODE STRUCT
		decryptedFileNodeStruct := userlib.SymDec(privateKeyForFileNode[:16], extractEncryptedFileNode) // decrypt the file node struct

		// UNMARSHALL THE FILE NODE STRUCT
		var userFileNode FileDataNode
		userFileNodeptr := &userFileNode
		err = json.Unmarshal(decryptedFileNodeStruct, userFileNodeptr)
		if err != nil {
			return nil, errors.New("error: unmarshall failed 2")
		}

		// APPEND THE CONTENT TO THE RUNNING VARIABLE
		fileContent = append(fileContent, userFileNode.FileData...)

		// RESET THE FILE NODE STRUCT TO GET THE NEXT FILE NODE IN THE LINKED LIST
		encryptedFileNodeStructWithHMAC, ok = userlib.DatastoreGet(userFileNode.NextPTR)
	}
	return fileContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// ------------------------------------ FILE OWNER CHECK ------------------------------------
	intermediateUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, errors.New("error: hashing the UUID failed - 828")
	}
	encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID)
	if ok == true { // iF YOU ARE THE FILE OWNER
		// ------------------------------------ DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
		// CHECK HMACS: authenticity/integrity check
		extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
		intermediateHMACRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
		if err != nil {
			return uuid.Nil, errors.New("error: hmac creation failed 1098")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
		if err != nil {
			return uuid.Nil, errors.New("error: hmac failed 2")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return uuid.Nil, errors.New("user struct was tampered with: line 844-4")
		}
		privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
		if err != nil {
			return uuid.Nil, errors.New("user struct was tampered with: 849")
		}
		// DECRYPT THE INTERMEDIATE STRUCT
		decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
		// UNMARSHALL THE INTERMEDIATE STRUCT
		var userIntermediateStruct Intermediate
		err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
		if err != nil {
			return uuid.Nil, errors.New("error: unmarshal failed: 859")
		}
		linkedListLocation := userIntermediateStruct.NextPTR     // this points to "Alice's" LL file struct
		fileOwnerPrivateKey := userIntermediateStruct.PrivateKey // argon2Key/can be the random key to open up the file

		// ------------------------------------ CREATE INVITE STRUCT ------------------------------------
		var inviteStruct Invitation
		locationOfInviteStruct, err := uuid.NewUUID()
		if err != nil {
			return uuid.Nil, errors.New("error2")
		}
		locationOfMiddleStruct, err := uuid.NewUUID() // the lockbox we create for the person we want to share with
		if err != nil {
			return uuid.Nil, errors.New("error2")
		}
		inviteStruct.NextPTR = locationOfMiddleStruct
		// STORE THE PRIVATE KEY FOR SYMMETRIC ENCRYPTION SO THAT the invite struct can SYMMETRICALLY decrypt the intermediate
		inviteStruct.PrivateKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
		// MARSHALL INVITE STRUCT

		marshalledInviteStruct, err := json.Marshal(inviteStruct)
		if err != nil {
			return uuid.Nil, errors.New("Error: Marshal failed for invite struct")
		}
		recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername + "encryptKey")
		if !ok {
			return uuid.Nil, errors.New(strings.ToTitle("file not found - 1143"))
		}
		// ENCRYPT INVITE STRUCT
		encryptedInviteStruct, err := userlib.PKEEnc(recipientPublicKey, marshalledInviteStruct)
		if err != nil {
			return uuid.Nil, errors.New("error2")
		}
		// CREATE A DIGITAL SIGNATURE ON THE INVITE STRUCT
		digitalSignatureForInvite, err := userlib.DSSign(userdata.PrivateKeyForDS, encryptedInviteStruct)
		if err != nil {
			return uuid.Nil, errors.New("The digital signature on the invite struct returned an error - line 937")
		}
		encryptedInviteStructWithDS := append(encryptedInviteStruct, digitalSignatureForInvite...)
		// SET - place this key (random uuid as key and value to be the new file node we added)
		userlib.DatastoreSet(locationOfInviteStruct, encryptedInviteStructWithDS)

		// ------------------------- CREATE INTERMEDIATE STRUCT -> with symmetric key encryption ----------------------------
		var intermediateStruct Intermediate
		intermediateStruct.NextPTR = linkedListLocation
		intermediateRootKey := fileOwnerPrivateKey
		intermediateStruct.PrivateKey = fileOwnerPrivateKey
		intermediateRootKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

		intermediateRootKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

		privateKeyForIntermediateStruct, err = userlib.HashKDF(intermediateRootKey, []byte("privateKey")) // PURPOSE: filename/username
		if err != nil {
			return uuid.Nil, errors.New("error: hmac creation failed")
		}
		// MARSHALL THE INTERMEDIATE STRUCT
		marshalledIntermediateStruct, err := json.Marshal(intermediateStruct)
		if err != nil {
			return uuid.Nil, errors.New("error: marshal failed")
		}
		// ENCRYPT THE INTERMEDIATE STRUCT
		encryptedIntermediateStruct := userlib.SymEnc(privateKeyForIntermediateStruct[:16], userlib.RandomBytes(16), marshalledIntermediateStruct)
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		privateKeyForIntermediateStructHMAC, err := userlib.HashKDF(intermediateRootKey, []byte("HMAC")) // PURPOSE: filename-username
		if err != nil {
			return uuid.Nil, errors.New("error: hmac creation failed")
		}
		HMACforIntermediateStruct, err := userlib.HMACEval(privateKeyForIntermediateStructHMAC[:16], encryptedIntermediateStruct)
		if err != nil {
			return uuid.Nil, errors.New("error: hmac creation failed")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedIntermediateStructWithHMAC := append(encryptedIntermediateStruct, HMACforIntermediateStruct...)

		// SET - key: random uuid, value: encrypted intermediate with HMAC
		userlib.DatastoreSet(locationOfMiddleStruct, encryptedIntermediateStructWithHMAC)

		//-------------------------------------- ADD TO THE HASHMAP -----------------------------------------
		dataStoreKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
		// CREATE THE UUID (FROM THE KEY)
		deterministicUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[0:16])
		if err != nil { 
			return uuid.Nil, errors.New("error: no initialized user")
		}

		// ERROR CHECK #2 - There is no initialized user for the given username.
		encryptedStructWithHMAC, ok := userlib.DatastoreGet(deterministicUUID) // GET THE VALUE (user struct)
		if ok == false {
			return uuid.Nil, errors.New("error: no initialized user")
		}
		// EXTRACT THE USER STRUCT - splice to get the user struct
		extractEncryptedUserStruct := encryptedStructWithHMAC[0 : len(encryptedStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err = userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
		if err != nil {
			return uuid.Nil, errors.New("error: hmac creation failed")
		}
		tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedUserStruct)
		if err != nil {
			return uuid.Nil, errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC = encryptedStructWithHMAC[len(encryptedStructWithHMAC)-64 : len(encryptedStructWithHMAC)]
		// ERROR CHECKS #3 + #4: user struct malicious action/integrity compromised AND user creditials are invalid
		authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return uuid.Nil, errors.New("user struct was tampered - line 248")
		}
		// DECRYPT THE USER STRUCT
		decryptedUserStruct := userlib.SymDec(dataStoreKey, extractEncryptedUserStruct) // decrypt the user struct with the given user key
		// UNMARSHALL THE USER STRUCT
		var userdataStructure User
		err = json.Unmarshal(decryptedUserStruct, &userdataStructure)
		if err != nil {
			return uuid.Nil, errors.New("error: unmarshal failed")
		}

		// ADD TO THE MAP: recipientUsername/file -> filename
		userdataStructure.FilesSharedByMe[recipientUsername+"/"+filename] = locationOfMiddleStruct
		
		marshalledStruct, err := json.Marshal(userdataStructure)
		if err != nil {
			return uuid.Nil, errors.New("error: marshal failed for struct")
		}
		// ENCRYPT THE STRUCT - encrypt the marshalled struct (the plaintext)
		encryptedStruct := userlib.SymEnc(dataStoreKey, userlib.RandomBytes(16), marshalledStruct)
		privateKeyForHMAC, err := userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
		if err != nil {
			return uuid.Nil, errors.New("error: private key for hmac failed")
		}
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		hmac, err := userlib.HMACEval(privateKeyForHMAC[:16], encryptedStruct)
		if err != nil {
			return uuid.Nil, errors.New("error: hmac creation failed")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedStructWithHMAC = append(encryptedStruct, hmac...)

		// STORE THE VALUE & KEY - value (encryptedStructWithHMAC) and key (UUID)
		userlib.DatastoreSet(deterministicUUID, encryptedStructWithHMAC)

		return locationOfInviteStruct, nil // return locationOfInviteStruct, nil
	}
	// IF YOU ARE NOT THE OWNER
	// ------------------------------------ CREATE INVITE STRUCT ------------------------------------
	var inviteStruct Invitation
	locationOfInviteStruct, err := uuid.NewUUID()
	if err != nil {
		return uuid.Nil, errors.New("error2 - 940")
	}

	inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "invite"))[:16])
	if err != nil {
		return uuid.Nil, errors.New("error: hashing the UUID failed - 818")
	}
	// ------------------------------------ DECRYPT THE OLD INVITE STRUCT ------------------------------------
	encryptedInviteFileWithDS, ok := userlib.DatastoreGet(inviteUUID) // gives you the invite struct
	if ok == false {
		return uuid.Nil, errors.New("error: hashing the UUID failed - 822/3")
	}
	// CHECK DIGITAL SIGNATURE
	extractEncryptedInviteStruct := encryptedInviteFileWithDS[0 : len(encryptedInviteFileWithDS)-256] // DSs are 256 bytes long!
	extractDS := encryptedInviteFileWithDS[len(encryptedInviteFileWithDS)-256 : len(encryptedInviteFileWithDS)]
	// GET THE SENDERUSERNAME'S PUBLIC KEY for rsa
	senderUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "sender"))[:16]) // get the sender username
	if err != nil {
		return uuid.Nil, errors.New("error: hashing the UUID failed - 818")
	}
	senderName, ok := userlib.DatastoreGet(senderUUID) // gives you the sender name
	// UNMARSHALL THE SENDER NAME
	var senderNameString string
	err = json.Unmarshal(senderName, &senderNameString)
	if err != nil {
		return uuid.Nil, errors.New("error: unmarshal failed")
	}
	senderPublicKey, ok := userlib.KeystoreGet(senderNameString + "signKey")
	if ok == false {
		return uuid.Nil, errors.New("authenticating DS did not work 1-9")
	}
	err = userlib.DSVerify(senderPublicKey, extractEncryptedInviteStruct, extractDS)
	if err != nil {
		return uuid.Nil, errors.New("authenticating DS did not work 1-11")
	}
	// DECRYPT THE INVITE STRUCT
	decryptedInviteStruct, err := userlib.PKEDec(userdata.PrivateKeyGen, extractEncryptedInviteStruct)
	if err != nil {
		return uuid.Nil, errors.New("authenticating DS did not work 2")
	}
	// UNMARSHALL THE INVITE STRUCT
	var userInviteStruct Invitation
	err = json.Unmarshal(decryptedInviteStruct, &userInviteStruct)
	if err != nil {
		return uuid.Nil, errors.New("error: unmarshal failed")
	}
	// RETRIEVE THE ARGON2KEY
	inviteArgon2Key := userInviteStruct.PrivateKey
	middleStructUUID := userInviteStruct.NextPTR

	// ------------------------------------ DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
	encryptedIntermediateFileWithHMAC, ok = userlib.DatastoreGet(middleStructUUID)
	extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
	intermediateHMACRootKey := inviteArgon2Key
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
	if err != nil {
		return uuid.Nil, errors.New("error: hmac creation failed 1098")
	}
	tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
	if err != nil {
		return uuid.Nil, errors.New("error: hmac failed 2")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
	authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return uuid.Nil, errors.New("user struct was tampered with: line 844-4")
	}
	privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
	if err != nil {
		return uuid.Nil, errors.New("user struct was tampered with: 849")
	}
	// DECRYPT THE INTERMEDIATE STRUCT
	decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE INTERMEDIATE STRUCT
	var userIntermediateStruct Intermediate
	err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
	if err != nil {
		return uuid.Nil, errors.New("error: unmarshal failed: 859")
	}
	linkedListLocation := userIntermediateStruct.NextPTR     // this points to "Alice's" LL file struct

	// -------------------- TRY TO DECRYPT THE LL - if you can, you are NOT a revoked user and can proceed ------------------
	_, ok = userlib.DatastoreGet(linkedListLocation)
	// ERROR CHECK #1: The given filename does not exist in the personal file namespace of the caller.
	if ok == false {
		return uuid.Nil, errors.New("cannot access the linked list")
	}
	// IF YOU CAN find the LL, that means it was NOT deleted -> this user was NOT revoked

	// ------------------------------ DECRYPT THE USER STRUCT TO GET THE updated info ------------------------------------
	dataStoreKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	// CREATE THE UUID (FROM THE KEY)
	deterministicUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[0:16])
	// ERROR CHECK #2 - There is no initialized user for the given username.
	encryptedStructWithHMAC, ok := userlib.DatastoreGet(deterministicUUID) // GET THE VALUE (user struct)
	if ok == false {
		return uuid.Nil, errors.New("error: no initialized user")
	}
	// EXTRACT THE USER STRUCT - splice to get the user struct
	extractEncryptedUserStruct := encryptedStructWithHMAC[0 : len(encryptedStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err = userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
	if err != nil {
		return uuid.Nil, errors.New("error: hmac creation failed")
	}
	tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedUserStruct)
	if err != nil {
		return uuid.Nil, errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC = encryptedStructWithHMAC[len(encryptedStructWithHMAC)-64 : len(encryptedStructWithHMAC)]
	// ERROR CHECKS #3 + #4: user struct malicious action/integrity compromised AND user creditials are invalid
	authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return uuid.Nil, errors.New("user struct was tampered - line 248")
	}
	// DECRYPT THE USER STRUCT
	decryptedUserStruct := userlib.SymDec(dataStoreKey, extractEncryptedUserStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE USER STRUCT
	var userdataStructure User
	err = json.Unmarshal(decryptedUserStruct, &userdataStructure)
	if err != nil {
		return uuid.Nil, errors.New("error: unmarshal failed")
	}
	// ------------------------------------------------------------------------------------------------------------

	locationOfMiddleStruct := userdataStructure.FilesSharedWithMe[userdataStructure.Username+"/"+filename]

	// ------------------------------ RE-ENCRYPT THE USER STRUCT ------------------------------------
	marshalledStruct, err := json.Marshal(userdataStructure)
	if err != nil {
		return uuid.Nil, errors.New("error: marshal failed for struct")
	}
	// ENCRYPT THE STRUCT - encrypt the marshalled struct (the plaintext)
	encryptedStruct := userlib.SymEnc(dataStoreKey, userlib.RandomBytes(16), marshalledStruct)
	privateKeyForHMAC, err := userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
	if err != nil {
		return uuid.Nil, errors.New("error: private key for hmac failed")
	}
	// "ENCRYPT THEN MAC" approach - mac over the ciphertext
	hmac, err := userlib.HMACEval(privateKeyForHMAC[:16], encryptedStruct)
	if err != nil {
		return uuid.Nil, errors.New("error: hmac creation failed")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedStructWithHMAC = append(encryptedStruct, hmac...)
	// STORE THE VALUE & KEY - value (encryptedStructWithHMAC) and key (UUID)
	userlib.DatastoreSet(deterministicUUID, encryptedStructWithHMAC)
	// ------------------------------------------------------------------------------------------------------------

	inviteStruct.NextPTR = locationOfMiddleStruct
	inviteStruct.PrivateKey = inviteArgon2Key

	// MARSHALL THE NEW INVITE STRUCT
	marshalledInviteStruct, err := json.Marshal(inviteStruct)
	if err != nil {
		return uuid.Nil, errors.New("Error: Marshal failed for invite struct")
	}
	recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername + "encryptKey")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("file not found - 1328"))
	}
	// ENCRYPT INVITE STRUCT
	encryptedInviteStruct, err := userlib.PKEEnc(recipientPublicKey, marshalledInviteStruct)
	if err != nil {
		return uuid.Nil, errors.New("error 2")
	}
	// CREATE A DIGITAL SIGNATURE ON THE INVITE STRUCT
	digitalSignatureForInvite, err := userlib.DSSign(userdata.PrivateKeyForDS, encryptedInviteStruct)
	if err != nil {
		return uuid.Nil, errors.New("The digital signature on the invite struct returned an error - line 1009")
	}
	encryptedInviteStructWithDS := append(encryptedInviteStruct, digitalSignatureForInvite...)

	// SET - place this key (random uuid as key and value to be the new file node we added)
	userlib.DatastoreSet(locationOfInviteStruct, encryptedInviteStructWithDS)

	return locationOfInviteStruct, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// give the corresponding file a name of filename in the caller’s personal namespace.
	// ERROR CHECK #2: The caller is unable to verify that the secure file share invitation pointed to by the given invitationPtr was created by senderUsername.
	// ERROR CHECK #3: The invitation is no longer valid due to revocation.
	// ERROR CHECK #4: The caller is unable to verify the integrity of the secure file share invitation pointed to by the given invitationPtr.

	// ERROR CHECK #1: The caller already has a file with the given filename in their personal file namespace.
	// CHECK - you own the file
	intermediateKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return errors.New("error: file already exists in the personal namespace of the user")
	}
	_, ok := userlib.DatastoreGet(intermediateKey)
	if ok == true {
		return errors.New("error: file already exists in the personal namespace of the user")
	}

	// CHECK - file is being shared with you
	inviteUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "invite"))[:16])
	if err != nil {
		return errors.New("error")
	}
	// check if the invite already exists
	_, ok = userlib.DatastoreGet(inviteUUID)
	if ok == true {
		return errors.New("error: file already exists in the personal namespace of the user")
	}

	// -------------------------- DECRYPT THE INVITE STRUCT -------------------------------
	encryptedInviteFileWithDS, ok := userlib.DatastoreGet(invitationPtr)
	if ok == false {
		return errors.New("error: file is not stored")
	}
	// CHECK DIGITAL SIGNATURE - ERROR CHECK #4
	extractEncryptedInviteStruct := encryptedInviteFileWithDS[0 : len(encryptedInviteFileWithDS)-256] // DSs are 256 bytes long!
	extractDS := encryptedInviteFileWithDS[len(encryptedInviteFileWithDS)-256 : len(encryptedInviteFileWithDS)]
	// GET THE SENDERUSERNAME'S PUBLIC KEY for rsa
	senderPublicKey, ok := userlib.KeystoreGet(senderUsername + "signKey")
	if ok == false {
		return errors.New("authenticating DS did not work 1-12")
	}
	err = userlib.DSVerify(senderPublicKey, extractEncryptedInviteStruct, extractDS)
	if err != nil {
		return errors.New("authenticating DS did not work 1-13")
	}
	// DECRYPT THE INVITE STRUCT - ERROR CHECK #3?
	decryptedInviteStruct, err := userlib.PKEDec(userdata.PrivateKeyGen, extractEncryptedInviteStruct)
	if err != nil {
		return errors.New("authenticating DS did not work 2")
	}
	// UNMARSHALL THE INVITE STRUCT
	var userInviteStruct Invitation
	err = json.Unmarshal(decryptedInviteStruct, &userInviteStruct)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}

	// -------------------------- SET IN DATASTORE - key: UUID that points to the invite, value: invite struct  -------------------------------
	inviteUUID, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "invite"))[:16])
	if err != nil {
		return errors.New("error")
	}
	// check if the invite exists

	// for every invite struct we had the encrypted intermediate struct as a UUID here and then you access it
	userlib.DatastoreSet(inviteUUID, encryptedInviteFileWithDS)

	//-------------------------------------- ADD THE HASHMAP VALUE -----------------------------------------
	dataStoreKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	// CREATE THE UUID (FROM THE KEY)
	deterministicUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[0:16])
	// ERROR CHECK #2 - There is no initialized user for the given username.
	encryptedStructWithHMAC, ok := userlib.DatastoreGet(deterministicUUID) // GET THE VALUE (user struct)
	if ok == false {
		return errors.New("error: no initialized user")
	}
	// EXTRACT THE USER STRUCT - splice to get the user struct
	extractEncryptedUserStruct := encryptedStructWithHMAC[0 : len(encryptedStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err := userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedUserStruct)
	if err != nil {
		return errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC := encryptedStructWithHMAC[len(encryptedStructWithHMAC)-64 : len(encryptedStructWithHMAC)]
	// ERROR CHECKS #3 + #4: user struct malicious action/integrity compromised AND user creditials are invalid
	authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return errors.New("user struct was tampered - line 248")
	}
	// DECRYPT THE USER STRUCT
	decryptedUserStruct := userlib.SymDec(dataStoreKey, extractEncryptedUserStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE USER STRUCT
	var userdataStructure User
	err = json.Unmarshal(decryptedUserStruct, &userdataStructure)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}

	// ADD TO THE MAP: recipientUsername/file -> filename
	userdataStructure.FilesSharedWithMe[userdataStructure.Username+"/"+filename] = userInviteStruct.NextPTR
	userdataStructure.MyFiles = append(userdata.MyFiles, filename)

	marshalledStruct, err := json.Marshal(userdataStructure)
	if err != nil {
		return errors.New("error: marshal failed for struct")
	}
	// ENCRYPT THE STRUCT - encrypt the marshalled struct (the plaintext)
	encryptedStruct := userlib.SymEnc(dataStoreKey, userlib.RandomBytes(16), marshalledStruct)
	privateKeyForHMAC, err := userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
	if err != nil {
		return errors.New("error: private key for hmac failed")
	}
	// "ENCRYPT THEN MAC" approach - mac over the ciphertext
	hmac, err := userlib.HMACEval(privateKeyForHMAC[:16], encryptedStruct)
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedStructWithHMAC = append(encryptedStruct, hmac...)
	// STORE THE VALUE & KEY - value (encryptedStructWithHMAC) and key (UUID)
	userlib.DatastoreSet(deterministicUUID, encryptedStructWithHMAC)

	senderUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "/" + filename + "sender"))[:16])
	if err != nil {
		return errors.New("error")
	}
	marshalledSenderName, err := json.Marshal(senderUsername)
	if err != nil {
		return errors.New("error: marshal failed")
	}
	// store the sender username to retrive in loadFile
	userlib.DatastoreSet(senderUUID, marshalledSenderName)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// ERROR CHECKS:
	// The given filename does not exist in the caller’s personal file namespace.
	// The given filename is not currently shared with recipientUsername.
	// Revocation cannot complete due to malicious action.

	// ------------------------------------ FILE OWNER CHECK ------------------------------------
	intermediateUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return errors.New("error: hashing the UUID failed - 828")
	}
	encryptedIntermediateFileWithHMAC, ok := userlib.DatastoreGet(intermediateUUID)
	if ok == false { // iF YOU ARE NOT THE FILE OWNER
		return errors.New("error: hashing the UUID failed - 1322")
	}
	// IF YOU ARE THE FILE OWNER 
	// ----------------------------- DECRYPT INTERMEDIATE STRUCT - to get the linked list uuid ------------------------
	// CHECK HMACS: authenticity/integrity check
	extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
	intermediateHMACRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
	if err != nil {
		return errors.New("error: hmac creation failed 1525")
	}
	tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
	if err != nil {
		return errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
	authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return errors.New("user struct was tampered with")
	}
	privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
	if err != nil {
		return errors.New("user struct was tampered with")
	}
	// DECRYPT THE INTERMEDIATE STRUCT
	decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE INTERMEDIATE STRUCT
	var userIntermediateStruct Intermediate
	err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}
	linkedListLocation := userIntermediateStruct.NextPTR

	// ----------------------------- DECRYPT THE LINKED LIST STRUCT ------------------------
	encryptedLinkedListStructWithHMAC, ok := userlib.DatastoreGet(linkedListLocation)
	if ok == false {
		return errors.New("error: encrypted file does not exist")
	}
	// CHECK HMACS: authenticity/integrity check
	extractEncryptedLinkedList := encryptedLinkedListStructWithHMAC[0 : len(encryptedLinkedListStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
	linkedListHMACRootKey := userIntermediateStruct.PrivateKey
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err = userlib.HashKDF(linkedListHMACRootKey, []byte("HMACforLL"))
	if err != nil {
		return errors.New("error: hmac creation failed 1564")
	}
	tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedLinkedList)
	if err != nil {
		return errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC = encryptedLinkedListStructWithHMAC[len(encryptedLinkedListStructWithHMAC)-64 : len(encryptedLinkedListStructWithHMAC)]
	authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return errors.New("user struct was tampered with")
	}
	privateKeyForLinkedListStruct, err := userlib.HashKDF(linkedListHMACRootKey, []byte("privateKeyforLL")) // PURPOSE: filename/username
	if err != nil {
		return errors.New("error: unmarshal failed")
	}
	// DECRYPT THE LINKED LIST STRUCT
	decryptedLinkedListStruct := userlib.SymDec(privateKeyForLinkedListStruct[:16], extractEncryptedLinkedList) // decrypt the user struct with the given user key
	// UNMARSHALL THE LINKED LIST STRUCT
	var userLinkedList FileLinkedList
	err = json.Unmarshal(decryptedLinkedListStruct, &userLinkedList)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}
	firstNodeFirstPTR := userLinkedList.FirstPTR // GET THE FIRST NODE'S LOCATION

	// ----------------------------- DECRYPT ALL THE FILE NODES -----------------------------------------------------------------------	
	encryptedFileNodeStructWithHMAC, ok := userlib.DatastoreGet(firstNodeFirstPTR) // GET THE FIRST NODE STRUCT ITSELF
	if !ok {
		return errors.New(strings.ToTitle("file not found - 1625"))
	}
	// DEFINE A NEW RANDOM KEY TO RE-ENCRYPT THE LL AND NODES
	randomKey := userlib.RandomBytes(16) 

	// LOOP OVER FILE NODES TO DECRYPT AND RE-ENCRYPT
	for ok == true { // if the UUID does exist - the file node does exist
		// CHECK HMACS - make sure hmac is not invalid
		extractEncryptedFileNode := encryptedFileNodeStructWithHMAC[0 : len(encryptedFileNodeStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
		fileNodeHMACRootKey := linkedListHMACRootKey // USE THE INTERMEDIATE UPDATED KEY

		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(fileNodeHMACRootKey, []byte("HMACforFileNode"))
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedFileNode)
		if err != nil {
			return errors.New("error: hmac failed")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedFileNodeStructWithHMAC[len(encryptedFileNodeStructWithHMAC)-64 : len(encryptedFileNodeStructWithHMAC)]

		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return errors.New("user struct was tampered with - line 691")
		}

		fileNodeRootKey := linkedListHMACRootKey
		privateKeyForFileNode, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode"))
		if err != nil {
			return errors.New("error: hmac creation failed - line 698")
		}

		// DECRYPT THE FILE NODE STRUCT
		decryptedFileNodeStruct := userlib.SymDec(privateKeyForFileNode[:16], extractEncryptedFileNode) // decrypt the file node struct

		// UNMARSHALL THE FILE NODE STRUCT
		var userFileNode FileDataNode
		userFileNodeptr := &userFileNode
		err = json.Unmarshal(decryptedFileNodeStruct, userFileNodeptr)
		if err != nil {
			return errors.New("error: unmarshall failed 2")
		}

		// ------------------------------ REENCRYPT THE FILE NODE STRUCTS WITH A NEW KEY + LOCATION -------------------------------------------
		fileNodeRootKey = randomKey
		privateKeyForFileNodeStruct, err := userlib.HashKDF(fileNodeRootKey, []byte("privateKeyforFileNode")) // PURPOSE: username/filename
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// MARSHALL THE FILE NODE STRUCT
		marshalledFileNodeStruct, err := json.Marshal(userFileNode)
		if err != nil {
			return errors.New("error: marshal failed")
		}
		// ENCRYPT THE FILE NODE STRUCT
		encryptedFileStruct := userlib.SymEnc(privateKeyForFileNodeStruct[:16], userlib.RandomBytes(16), marshalledFileNodeStruct)
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		privateKeyForFileNodeHMAC, err := userlib.HashKDF(fileNodeRootKey, []byte("HMACforFileNode")) // PURPOSE: username-filename
		HMAC, err := userlib.HMACEval(privateKeyForFileNodeHMAC[:16], encryptedFileStruct)
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedFileStructWithHMAC := append(encryptedFileStruct, HMAC...)

		// SET - SAVING THE CHANGES
		userlib.DatastoreSet(firstNodeFirstPTR, encryptedFileStructWithHMAC)

		// RESET THE FILE NODE STRUCT TO GET THE NEXT FILE NODE IN THE LINKED LIST
		encryptedFileNodeStructWithHMAC, ok = userlib.DatastoreGet(userFileNode.NextPTR)

		// RESET THE KEY TO THE NEXT KEY
		firstNodeFirstPTR = userFileNode.NextPTR 
	}

	// ------------------------------ REENCRYPT THE LINKED LIST STRUCT WITH A NEW KEY + LOCATION -------------------------------------------
	linkedListNEWRootKey := randomKey    // random key bc revoked user cannot be able to "guess" the key
	privateKeyForLinkedList, err := userlib.HashKDF(linkedListNEWRootKey, []byte("privateKeyforLL"))
	if err != nil {
		return errors.New("error: private key creation failed 2")
	}
	marshalledLinkedListStruct, err := json.Marshal(userLinkedList)
	if err != nil {
		return errors.New("error: marshal failed")
	}
	encryptedLinkedListStruct := userlib.SymEnc(privateKeyForLinkedList[:16], userlib.RandomBytes(16), marshalledLinkedListStruct)
	privateKeyForLinkedListHMAC, err := userlib.HashKDF(linkedListNEWRootKey, []byte("HMACforLL")) // CHANGE THE PURPOSE HERE
	if err != nil {
		return errors.New("error: hmac creation failed 3")
	}
	HMACforLinkedList, err := userlib.HMACEval(privateKeyForLinkedListHMAC[:16], encryptedLinkedListStruct)
	if err != nil {
		return errors.New("error: hmac creation failed 4")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedLinkedListStructWithHMAC = append(encryptedLinkedListStruct, HMACforLinkedList...)
	// CREATE A NEW LINKEDLIST LOCATION
	newLinkedListLocation := uuid.New()
	// SET THE LINKED LIST STRUCT
	userlib.DatastoreSet(newLinkedListLocation, encryptedLinkedListStructWithHMAC)

	// --------------------------------- UPDATE THE NEXT PTR AND KEY FOR THE INTERMEDIATE STRUCT -----------------------------
	userIntermediateStruct.NextPTR = newLinkedListLocation
	userIntermediateStruct.PrivateKey = linkedListNEWRootKey // this is the key used to encrypt the file LL

	intermediateRootKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	privateKeyForIntermediateStruct, err = userlib.HashKDF(intermediateRootKey, []byte("privateKey")) // PURPOSE: filename/username
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	// MARSHALL THE INTERMEDIATE STRUCT
	marshalledIntermediateStruct, err := json.Marshal(userIntermediateStruct)
	if err != nil {
		return errors.New("error: marshal failed")
	}
	// ENCRYPT THE INTERMEDIATE STRUCT
	encryptedIntermediateStruct := userlib.SymEnc(privateKeyForIntermediateStruct[:16], userlib.RandomBytes(16), marshalledIntermediateStruct)
	// "ENCRYPT THEN MAC" approach - mac over the ciphertext
	privateKeyForIntermediateStructHMAC, err := userlib.HashKDF(intermediateRootKey, []byte("HMAC")) // PURPOSE: filename-username
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	HMACforIntermediateStruct, err := userlib.HMACEval(privateKeyForIntermediateStructHMAC[:16], encryptedIntermediateStruct)
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedIntermediateStructWithHMAC := append(encryptedIntermediateStruct, HMACforIntermediateStruct...)
	// SET THE INTERMEDIATE STRUCT
	userlib.DatastoreSet(intermediateUUID, encryptedIntermediateStructWithHMAC)

	// ---------------------------------------- DECRYPT THE USER STRUCT -----------------------------------------
	dataStoreKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	// CREATE THE UUID (FROM THE KEY)
	deterministicUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[0:16])
	// ERROR CHECK #2 - There is no initialized user for the given username.
	encryptedStructWithHMAC, ok := userlib.DatastoreGet(deterministicUUID) // GET THE VALUE (user struct)
	if ok == false {
		return errors.New("error: no initialized user")
	}
	// EXTRACT THE USER STRUCT - splice to get the user struct
	extractEncryptedUserStruct := encryptedStructWithHMAC[0 : len(encryptedStructWithHMAC)-64] // HMACS ARE 64 bytes long!!
	// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
	privateKeyForTempHMAC, err = userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	tempHMAC, err = userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedUserStruct)
	if err != nil {
		return errors.New("error: hmac failed")
	}
	// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
	extractHMAC = encryptedStructWithHMAC[len(encryptedStructWithHMAC)-64 : len(encryptedStructWithHMAC)]
	// ERROR CHECKS #3 + #4: user struct malicious action/integrity compromised AND user creditials are invalid
	authenticateHMAC = userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
	if authenticateHMAC == false {
		return errors.New("user struct was tampered - line 248")
	}
	// DECRYPT THE USER STRUCT
	decryptedUserStruct := userlib.SymDec(dataStoreKey, extractEncryptedUserStruct) // decrypt the user struct with the given user key
	// UNMARSHALL THE USER STRUCT
	var userdataStructure User
	err = json.Unmarshal(decryptedUserStruct, &userdataStructure)
	if err != nil {
		return errors.New("error: unmarshal failed")
	}

	// DELETE person who no longer has access
	delete(userdataStructure.FilesSharedByMe, recipientUsername+"/"+filename)

	// DELETE the old LL file struct from the datastore
	userlib.DatastoreDelete(linkedListLocation)

	// --------------------------------- UPDATE THE KEYS FOR EVERYONE WHO STILL HAS ACCESS -----------------------------
	for _, uuidOfIntermediateBeingShared := range userdataStructure.FilesSharedByMe {
		//------------------------------------ SYMMETRICALLY DECRYPT THE INTERMEDIATE STRUCT ------------------------------------
		encryptedIntermediateFileWithHMAC, ok = userlib.DatastoreGet(uuidOfIntermediateBeingShared)
		// CHECK HMACS: authenticity/integrity check
		extractEncryptedIntermediateStruct := encryptedIntermediateFileWithHMAC[0 : len(encryptedIntermediateFileWithHMAC)-64] // HMACS ARE 64 bytes long!!
		// CREATE A TEMP HMAC ON THE CIPHERTEXT - should return the same hmac bc the hmac func is deterministic
		privateKeyForTempHMAC, err := userlib.HashKDF(intermediateHMACRootKey, []byte("HMAC"))
		if err != nil {
			return errors.New("error: hmac creation failed 1659")
		}
		tempHMAC, err := userlib.HMACEval(privateKeyForTempHMAC[:16], extractEncryptedIntermediateStruct)
		if err != nil {
			return errors.New("error: hmac failed 2")
		}
		// EXTRACT THE ORIGINAL HMAC FROM THE CIPHERTEXT
		extractHMAC := encryptedIntermediateFileWithHMAC[len(encryptedIntermediateFileWithHMAC)-64 : len(encryptedIntermediateFileWithHMAC)]
		authenticateHMAC := userlib.HMACEqual(extractHMAC, tempHMAC) // authenticate the mac - check if it is invalid (invalid if MSG has been tampered with)
		if authenticateHMAC == false {
			return errors.New("user struct was tampered with: line 844-1")
		}
		privateKeyForIntermediateStruct, err := userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
		if err != nil {
			return errors.New("user struct was tampered with: 849")
		}
		// DECRYPT THE INTERMEDIATE STRUCT
		decryptedIntermediateStruct := userlib.SymDec(privateKeyForIntermediateStruct[:16], extractEncryptedIntermediateStruct) // decrypt the user struct with the given user key
		// UNMARSHALL THE INTERMEDIATE STRUCT
		var userIntermediateStruct Intermediate
		err = json.Unmarshal(decryptedIntermediateStruct, &userIntermediateStruct)
		if err != nil {
			return errors.New("error: unmarshal failed: 859")
		}
		// 2) CHANGE the argon2key of the intermediate to the new random key of the linked list
		userIntermediateStruct.PrivateKey = randomKey
		// 3) CHANGE the next ptr of the intermediate to point to the new uuid of the linked list file
		userIntermediateStruct.NextPTR = newLinkedListLocation

		// SYMMETRICALLY ENCRYPT TO SAVE THESE CHANGES
		privateKeyForIntermediateStruct, err = userlib.HashKDF(intermediateHMACRootKey, []byte("privateKey")) // PURPOSE: filename/username
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// MARSHALL THE INTERMEDIATE STRUCT
		marshalledIntermediateStruct, err = json.Marshal(userIntermediateStruct)
		if err != nil {
			return errors.New("error: marshal failed")
		}
		// ENCRYPT THE INTERMEDIATE STRUCT
		encryptedIntermediateStruct := userlib.SymEnc(privateKeyForIntermediateStruct[:16], userlib.RandomBytes(16), marshalledIntermediateStruct)
		// "ENCRYPT THEN MAC" approach - mac over the ciphertext
		privateKeyForIntermediateStructHMAC, err := userlib.HashKDF(intermediateRootKey, []byte("HMAC")) // PURPOSE: filename-username
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		HMACforIntermediateStruct, err := userlib.HMACEval(privateKeyForIntermediateStructHMAC[:16], encryptedIntermediateStruct)
		if err != nil {
			return errors.New("error: hmac creation failed")
		}
		// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
		encryptedIntermediateStructWithHMAC := append(encryptedIntermediateStruct, HMACforIntermediateStruct...)
		// SET - key: filename/username, value: encrypted intermediate
		userlib.DatastoreSet(uuidOfIntermediateBeingShared, encryptedIntermediateStructWithHMAC)
	}

	// ---------- RE-ENCRYPT THE USER STRUCT ---------
	marshalledStruct, err := json.Marshal(userdataStructure)
	if err != nil {
		return errors.New("error: marshal failed for struct")
	}
	// ENCRYPT THE STRUCT - encrypt the marshalled struct (the plaintext)
	encryptedStruct := userlib.SymEnc(dataStoreKey, userlib.RandomBytes(16), marshalledStruct)
	privateKeyForHMAC, err := userlib.HashKDF(dataStoreKey, []byte(userdata.Username))
	if err != nil {
		return errors.New("error: private key for hmac failed")
	}
	// "ENCRYPT THEN MAC" approach - mac over the ciphertext
	hmac, err := userlib.HMACEval(privateKeyForHMAC[:16], encryptedStruct)
	if err != nil {
		return errors.New("error: hmac creation failed")
	}
	// CONCATENATE THE HMAC AND ENCRYPTEDSTRUCT
	encryptedStructWithHMAC = append(encryptedStruct, hmac...)
	// STORE THE VALUE & KEY - value (encryptedStructWithHMAC) and key (UUID)
	userlib.DatastoreSet(deterministicUUID, encryptedStructWithHMAC)

	return nil
}


