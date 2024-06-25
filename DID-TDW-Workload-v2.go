// Listing of the workload code incorporating the DID:TDW generation.
// MPC-CMP protocol for threshold key generation and signing,
// while using CRYSTALS-Kyber for post-quantum cryptography.
// It's designed to run in a Google Cloud Confidential Space environment,
// by confidentially integrating with scalable Google Cloud KMS and Storage for 
// handling encrypted votes and performing a privacy-preserving vote count.
// https://github.com/vSpaceVote/vSpaceVote/blob/main/DID-TDW-Workload-v1.go
// TODO: "c001_PROJECT_NUMBER"
package main
import (
    "context"
    "crypto/rand"
    "fmt"
    "math/big"
    "strings"
    "time"
    "io/ioutil"
    kms "cloud.google.com/go/kms/apiv1"
    "cloud.google.com/go/storage"
    "google.golang.org/api/option"
    kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
    "github.com/mr-shifu/mpc-lib/protocols/cmp"
    "github.com/mr-shifu/mpc-lib/core/math/curve"
    "github.com/mr-shifu/mpc-lib/core/party"
    "github.com/mr-shifu/mpc-lib/core/protocol"
    "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
    "github.com/mr-shifu/mpc-lib/pkg/mpc/message"
    "github.com/mr-shifu/mpc-lib/pkg/mpc/state"
    "github.com/cloudflare/circl/kem/kyber"
    "go.dedis.ch/kyber/v3"
    "go.dedis.ch/kyber/v3/group/edwards25519"
    "go.dedis.ch/kyber/v3/share"
    "go.dedis.ch/kyber/v3/share/vss/pedersen"
)
type collaborator struct {
    name         string
    wipName      string
    sa           string
    keyName      string
    inputBucket  string
    inputFile    string
    outputBucket string
    outputFile   string
    id           party.ID
    did          string
}
const (
    threshold = 2
    totalParties = 3
    SCID_PLACEHOLDER = "SCID_PLACEHOLDER"
)
// ==========================
// USER VARIABLES SECTION
// ==========================
// c001's values
const collaborator1Name string = "c001"
const collaborator1EncryptedSVoteFileName string = "c001-encrypted-vote-file"
const collaborator1BucketInputName string = "c001-input-bucket-name"
const collaborator1BucketOutputName string = "c001-results-bucket-name"
const collaborator1BucketOutputFileName string = "c001-results-file-name"
const collaborator1KMSKeyringName string = "c001-keyring-name"
const collaborator1KMSKeyName string = "c001-key-name"
const collaborator1ProjectName string = "c001-project-id"
// gcloud projects describe c001-project-id --format="value(projectNumber)"
const collaborator1ProjectNumber string = ""
const collaborator1PoolName string = "c001-pool-name"
const collaborator1ServiceAccountName string = "c001-service-account-name"
// c999's values
const collaborator2Name string = "c999"
const collaborator2EncryptedSVoteFileName string = "c999-encrypted-vote-file"
const collaborator2BucketInputName string = "c999-input-bucket-name"
const collaborator2BucketOutputName string = "c999-results-bucket-name"
const collaborator2BucketOutputFileName string = "c999-results-file-name"
const collaborator2KMSKeyringName string = "c999-keyring-name"
const collaborator2KMSKeyName string = "c999-key-name"
const collaborator2ProjectName string = "c999-project-id"
// gcloud projects describe c999-project-id --format="value(projectNumber)"
const collaborator2ProjectNumber string = ""
const collaborator2PoolName string = "c999-pool-name"
const collaborator2ServiceAccountName string = "c999-service-account-name"
// END USER VARIABLES SECTION
// ==========================
//! var voters = []voter{
// collaborators_n=2
// collaborators_n=20000000
var collaborators = [2]collaborator{
  {
    collaborator1Name,
    "projects/" + collaborator1ProjectNumber + "/locations/global/workloadIdentityPools/" + collaborator1PoolName + "/providers/attestation-verifier",
    collaborator1ServiceAccountName + "@" + collaborator1ProjectName + ".iam.gserviceaccount.com",
    "projects/" + collaborator1ProjectName + "/locations/global/keyRings/" + collaborator1KMSKeyringName + "/cryptoKeys/" + collaborator1KMSKeyName,
    collaborator1BucketInputName,
    collaborator1EncryptedSalaryFileName,
    collaborator1BucketOutputName,
    collaborator1BucketOutputFileName,
    // id
    // did
  },
  {
    collaborator2Name,
    "projects/" + collaborator2ProjectNumber + "/locations/global/workloadIdentityPools/" + collaborator2PoolName + "/providers/attestation-verifier",
    collaborator2ServiceAccountName + "@" + collaborator2ProjectName + ".iam.gserviceaccount.com",
    "projects/" + collaborator2ProjectName + "/locations/global/keyRings/" + collaborator2KMSKeyringName + "/cryptoKeys/" + collaborator2KMSKeyName,
    collaborator2BucketInputName,
    collaborator2EncryptedSalaryFileName,
    collaborator2BucketOutputName,
    collaborator2BucketOutputFileName,
    // id
    // did
  },
}
/* var voters = []voter{
    {
	name:         "Alex",
        wipName:      "projects/ALEX_PROJECT_NUMBER/locations/global/workloadIdentityPools/ALEX_POOL_NAME/providers/attestation-verifier",
        sa:           "ALEX_SERVICE_ACCOUNT_NAME@ALEX_PROJECT_ID.iam.gserviceaccount.com",
        keyName:      "projects/ALEX_PROJECT_ID/locations/global/keyRings/ALEX_KEYRING_NAME/cryptoKeys/ALEX_KEY_NAME",
        inputBucket:  "ALEX_INPUT_BUCKET_NAME",
        inputFile:    "ALEX_ENCRYPTED_VOTE_FILE",
        outputBucket: "ALEX_RESULTS_BUCKET_NAME",
        outputFile:   "ALEX_RESULTS_FILE_NAME",
    },
    {
        name:         "Bola",
        wipName:      "projects/BOLA_PROJECT_NUMBER/locations/global/workloadIdentityPools/BOLA_POOL_NAME/providers/attestation-verifier",
        sa:           "BOLA_SERVICE_ACCOUNT_NAME@BOLA_PROJECT_ID.iam.gserviceaccount.com",
        keyName:      "projects/BOLA_PROJECT_ID/locations/global/keyRings/BOLA_KEYRING_NAME/cryptoKeys/BOLA_KEY_NAME",
        inputBucket:  "BOLA_INPUT_BUCKET_NAME",
        inputFile:    "BOLA_ENCRYPTED_VOTE_FILE",
        outputBucket: "BOLA_RESULTS_BUCKET_NAME",
        outputFile:   "BOLA_RESULTS_FILE_NAME",
    },
} */
const credentialConfig = `{
    "type": "external_account",
    "audience": "//iam.googleapis.com/%s",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
        "file": "/run/container_launcher/attestation_verifier_claims_token"
    },
    "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
}`
func GenerateDID(domain string) (string, error) {
    pub, _, err := kyber.KeyGen768(rand.Reader)
    if err != nil {
        return "", err
    }
    did := fmt.Sprintf("did:tdw:%s:%s", domain, SCID_PLACEHOLDER)
    return did, nil
}
func getSVote(ctx context.Context, storageClient *storage.Client, cw collaborator) (int, error) {
    encryptedBytes, err := getFile(ctx, storageClient, cw.inputBucket, cw.inputFile)
    if err != nil {
        return 0, err
    }
    decryptedByte, err := decryptByte(ctx, cw.keyName, cw.sa, cw.wipName, encryptedBytes)
    if err != nil {
        return 0, err
    }
    decryptedNumber := strings.TrimSpace(string(decryptedByte))
    num, err := strconv.Atoi(decryptedNumber)
    if err != nil {
        return 0, err
    }
    return num, nil
}
func decryptByte(ctx context.Context, keyName, trustedServiceAccountEmail, wippro string, encryptedData []byte) ([]byte, error) {
    cc := fmt.Sprintf(credentialConfig, wippro, trustedServiceAccountEmail)
    kmsClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsJSON([]byte(cc)))
    if err != nil {
        return nil, fmt.Errorf("creating a new KMS client with federated credentials: %w", err)
    }
    decryptRequest := &kmspb.DecryptRequest{
        Name:       keyName,
        Ciphertext: encryptedData,
    }
    decryptResponse, err := kmsClient.Decrypt(ctx, decryptRequest)
    if err != nil {
        return nil, fmt.Errorf("could not decrypt ciphertext: %w", err)
    }
    return decryptResponse.Plaintext, nil
}
func getFile(ctx context.Context, c *storage.Client, bucketName string, objPath string) ([]byte, error) {
    bucketHandle := c.Bucket(bucketName)
    objectHandle := bucketHandle.Object(objPath)
    objectReader, err := objectHandle.NewReader(ctx)
    if err != nil {
        return nil, err
    }
    defer objectReader.Close()
    return objectReader.ReadAll()
}
func main() {
    fmt.Println("Confidential vSPACE workload started")
    ctx := context.Background()
    storageClient, err := storage.NewClient(ctx)
    if err != nil {
        panic(err)
    }
    msgstore := message.NewInMemoryMessageStore()
    bcststore := message.NewInMemoryMessageStore()
    keycfgstore := state.NewInMemoryKeyConfigStore()
    signcfgstore := state.NewInMemorySignConfigStore()
    keystatestore := state.NewInMemoryKeyStateStore()
    signstatestore := state.NewInMemorySignStateStore()
    mpcInstance := cmp.NewMPC(
        nil, nil, nil,
        keycfgstore, signcfgstore,
        keystatestore, signstatestore,
        msgstore, bcststore,
        nil,
    )
    keyID := "threshold-key"
    ids := make([]party.ID, len(collaborators))
    for i := range collaborators {
        ids[i] = party.ID(fmt.Sprintf("party-%d", i))
        collaborators[i].id = ids[i]
        collaborators[i].did, err = GenerateDID(collaborators[i].name)
        if err != nil {
            panic(err)
        }
    }
    keycfg := config.NewKeyConfig(keyID, curve.Secp256k1{}, threshold, ids[0], ids)  
    handlers := make([]*protocol.Handler, len(collaborators))
    for i, cw := range collaborators {
        h, err := protocol.NewMultiHandler(mpcInstance.Keygen(keycfg, nil), nil)
        if err != nil {
            panic(err)
        }
        handlers[i] = h
    }
    for i := 0; i < 3; i++ {
        for j, h := range handlers {
            msg, err := h.Listen()
            if err != nil {
                panic(err)
            }
            if msg != nil {
                for k, oh := range handlers {
                    if j != k {
                        err = oh.Accept(msg)
                        if err != nil {
                            panic(err)
                        }
                    }
                }
            }
        }
    }
    keyShares := make([]*big.Int, len(collaborators))
    for i, h := range handlers {
        r, err := h.Result()
        if err != nil {
            panic(err)
        }
        c := r.(*cmp.Config)
        keyShares[i] = c.Share
    }
    votes := make([]*big.Int, len(collaborators))
    for i, cw := range collaborators {
        vote, err := getSVote(ctx, storageClient, cw)
        if err != nil {
            panic(err)
        }
        votes[i] = big.NewInt(int64(vote))
    }
    signedVotes := make([]*big.Int, len(votes))
    for i, vote := range votes {
        signConfig := config.NewSignConfig(keyID, vote)
        h, err := protocol.NewMultiHandler(mpcInstance.Sign(signConfig, nil), nil)
        if err != nil {
            panic(err)
        }      
        for j := 0; j < 3; j++ {
            msg, err := h.Listen()
            if err != nil {
                panic(err)
            }
            if msg != nil {
                for k, oh := range handlers {
                    if i != k {
                        err = oh.Accept(msg)
                        if err != nil {
                            panic(err)
                        }
                    }
                }
            }
        }
        r, err := h.Result()
        if err != nil {
            panic(err)
        }
        signature := r.(*cmp.Signature)
        signedVotes[i] = signature.R
    }
    voteCount := make(map[string]int)
    for _, vote := range signedVotes {
        voteStr := vote.String()
        voteCount[voteStr]++
    }
    mostVotes := 0
    winners := []string{}
    for candidate, count := range voteCount {
        if count > mostVotes {
            mostVotes = count
            winners = []string{candidate}
        } else if count == mostVotes {
            winners = append(winners, candidate)
        }
    }
    var result string
    if len(winners) == 1 {
        result = fmt.Sprintf("The winner is candidate %s with %d votes", winners[0], mostVotes)
    } else if len(winners) > 1 {
        result = fmt.Sprintf("It's a tie between candidates %s with %d votes each", strings.Join(winners, ", "), mostVotes)
    } else {
        result = "No votes were cast"
    }
    now := time.Now()
    for _, cw := range collaborators {
        outputWriter := storageClient.Bucket(cw.outputBucket).Object(fmt.Sprintf("%s-%d", cw.outputFile, now.Unix())).NewWriter(ctx)
        _, err = outputWriter.Write([]byte(result))
        if err != nil {
            fmt.Printf("Could not write: %cw", err)
            panic(err)
        }
        if err = outputWriter.Close(); err != nil {
            fmt.Printf("Could not close: %cw", err)
            panic(err)
        }
    }
}
// REF/Inspired by: 
// https://github.com/bcgov/trustdidweb/issues/6
// https://raw.githubusercontent.com/mr-shifu/mpc-lib/master/protocols/cmp/cmp_test.go
// https://gitlab.kingston.ac.uk/K1531112/verifiable-secret-sharing/blob/master/fvss.py
// https://raw.githubusercontent.com/vSpaceVote/vSpaceVote/main/DID-TDW-Workload-v1.go
