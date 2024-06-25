// Partial listing of the workload code incorporating the DID:TDW generation, MPC-CMP protocol for threshold key generation and signing, while using CRYSTALS-Kyber for post-quantum cryptography. It's designed to run in a Google Cloud Confidential Space environment, handling encrypted votes and performing a secure, privacy-preserving vote count.
// https://github.com/vSpaceVote/vSpaceVote/blob/main/vSpaceVote-DID-TDW-Confidential-Workload-P1.go
package main
import (
    "context"
    "crypto/rand"
    "fmt"
    "math/big"
    "strings"
    "time"
    kms "cloud.google.com/go/kms/apiv1"
    "cloud.google.com/go/storage"
    "google.golang.org/api/option"
    kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
    "github.com/cloudflare/circl/kem/kyber"
    "github.com/mr-shifu/mpc-lib/protocols/cmp"
	// TODO: cmp_test.go imports
)
type voter struct {
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
var voters = []voter{
    {
        // TODO: 1st Collaborator, as in Source Code Template
    },
    {
        // TODO: 2nd Collaborator, as in Source Code Template
    },
}
const credentialConfig = `{
    // TODO: Same as Source Code Template
}`
func GenerateDID(domain string) (string, error) {
    pub, _, err := kyber.KeyGen768(rand.Reader)
    if err != nil {
        return "", err
    }
    did := fmt.Sprintf("did:tdw:%s:%s", domain, SCID_PLACEHOLDER)
    return did, nil
}
func getVote(ctx context.Context, storageClient *storage.Client, v voter) (int, error) {
    encryptedBytes, err := getFile(ctx, storageClient, v.inputBucket, v.inputFile)
    if err != nil {
        return 0, err
    }
    decryptedByte, err := decryptByte(ctx, v.keyName, v.sa, v.wipName, encryptedBytes)
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
    // TODO: Same as Source Code Template
    return decryptResponse.Plaintext, nil
}
func getFile(ctx context.Context, c *storage.Client, bucketName string, objPath string) ([]byte, error) {
    // TODO: Same as Source Code Template
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
    ids := make([]party.ID, len(voters))
    for i := range voters {
        ids[i] = party.ID(fmt.Sprintf("party-%d", i))
        voters[i].id = ids[i]
        voters[i].did, err = GenerateDID(voters[i].name)
        if err != nil {
            panic(err)
        }
    }
    keycfg := config.NewKeyConfig(keyID, curve.Secp256k1{}, threshold, ids[0], ids)  
    handlers := make([]*protocol.Handler, len(voters))
    for i, v := range voters {
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
    keyShares := make([]*big.Int, len(voters))
    for i, h := range handlers {
        r, err := h.Result()
        if err != nil {
            panic(err)
        }
        c := r.(*cmp.Config)
        keyShares[i] = c.Share
    }
    votes := make([]*big.Int, len(voters))
    for i, v := range voters {
        vote, err := getVote(ctx, storageClient, v)
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
    for _, v := range voters {
        outputWriter := storageClient.Bucket(v.outputBucket).Object(fmt.Sprintf("%s-%d", v.outputFile, now.Unix())).NewWriter(ctx)
        _, err = outputWriter.Write([]byte(result))
        if err != nil {
            fmt.Printf("Could not write: %v", err)
            panic(err)
        }
        if err = outputWriter.Close(); err != nil {
            fmt.Printf("Could not close: %v", err)
            panic(err)
        }
    }
}
// REF/Inspired by: 
// https://github.com/bcgov/trustdidweb/issues/6
// https://raw.githubusercontent.com/mr-shifu/mpc-lib/master/protocols/cmp/cmp_test.go
// https://raw.githubusercontent.com/vSpaceVote/vSpaceVote/main/vSpaceVote-DID-TDW-Confidential-Workload-P1.go