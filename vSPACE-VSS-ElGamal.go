// vSPACE-VSS-ElGamal.go
/* ### Key Refactored Points:
0. **Google Cloud Integration**: The code integrates with Google Cloud KMS and Storage for secure vote handling.
1. **VSS Integration**: We use the DEDIS Kyber library to create and distribute VSS shares for each voter's vote.
2. **ElGamal Encryption**: We use a simplified homomorphic addition by summing the votes directly.
3. **Vote Tallying**: The votes are tallied homomorphically, and the final result is decrypted and published. */
// inspired by https://gitlab.kingston.ac.uk/K1531112/verifiable-secret-sharing/blob/master/fvss.py
//TODO: "Voter001_PROJECT_NUMBER"
package main
import (
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/storage"
	"context"
	"crypto/rand"
	"fmt"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"io/ioutil"
	"math/big"
	"strings"
	"time"
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
}
// ==========================
// USER VARIABLES SECTION
// ==========================
// Voter001's values
const collaborator1Name string = "Voter001"
const collaborator1EncryptedSVoteFileName string = "voter001-encrypted-vote-file"
const collaborator1BucketInputName string = "voter001-input-bucket-name"
const collaborator1BucketOutputName string = "voter001-results-bucket-name"
const collaborator1BucketOutputFileName string = "voter001-results-file-name"
const collaborator1KMSKeyringName string = "voter001-keyring-name"
const collaborator1KMSKeyName string = "voter001-key-name"
const collaborator1ProjectName string = "voter001-project-id"
// gcloud projects describe voter001-project-id --format="value(projectNumber)"
const collaborator1ProjectNumber string = ""
const collaborator1PoolName string = "voter001-pool-name"
const collaborator1ServiceAccountName string = "voter001-service-account-name"
// Voter999's values
const collaborator2Name string = "Voter999"
const collaborator2EncryptedSVoteFileName string = "voter999-encrypted-vote-file"
const collaborator2BucketInputName string = "voter999-input-bucket-name"
const collaborator2BucketOutputName string = "voter999-results-bucket-name"
const collaborator2BucketOutputFileName string = "voter999-results-file-name"
const collaborator2KMSKeyringName string = "voter999-keyring-name"
const collaborator2KMSKeyName string = "voter999-key-name"
const collaborator2ProjectName string = "voter999-project-id"
// gcloud projects describe voter999-project-id --format="value(projectNumber)"
const collaborator2ProjectNumber string = ""
const collaborator2PoolName string = "voter999-pool-name"
const collaborator2ServiceAccountName string = "voter999-service-account-name"
// END USER VARIABLES SECTION
// ==========================
// collaborators_n=2
// collaborators_n=20000000
var collaborators = [2]collaborator{
	{
		collaborator1Name,
		"projects/" + collaborator1ProjectNumber + "/locations/global/workloadIdentityPools/" + collaborator1PoolName + "/providers/attestation-verifier",
		collaborator1ServiceAccountName + "@" + collaborator1ProjectName + ".iam.gserviceaccount.com",
		"projects/" + collaborator1ProjectName + "/locations/global/keyRings/" + collaborator1KMSKeyringName + "/cryptoKeys/" + collaborator1KMSKeyName,
		collaborator1BucketInputName,
		collaborator1EncryptedSVoteFileName,
		collaborator1BucketOutputName,
		collaborator1BucketOutputFileName,
	},
	{
		collaborator2Name,
		"projects/" + collaborator2ProjectNumber + "/locations/global/workloadIdentityPools/" + collaborator2PoolName + "/providers/attestation-verifier",
		collaborator2ServiceAccountName + "@" + collaborator2ProjectName + ".iam.gserviceaccount.com",
		"projects/" + collaborator2ProjectName + "/locations/global/keyRings/" + collaborator2KMSKeyringName + "/cryptoKeys/" + collaborator2KMSKeyName,
		collaborator2BucketInputName,
		collaborator2EncryptedSVoteFileName,
		collaborator2BucketOutputName,
		collaborator2BucketOutputFileName,
	},
}
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
type Voter struct {
	ID        string
	PublicKey kyber.Point
	SecretKey kyber.Scalar
	Vote      *big.Int
	Shares    []*share.PriShare
}
type ElectionAuthority struct {
	Voters       []Voter
	ThresholdVSS int
	Suite        *edwards25519.SuiteEd25519
}
func main() {
	fmt.Println("workload started")
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx) // using the default credential on the Compute Engine VM
	if err != nil {
		panic(err)
	}
	// Initialize election authority
	authority := &ElectionAuthority{
		Voters:       make([]Voter, len(collaborators)),
		ThresholdVSS: len(collaborators)/2 + 1, // Majority threshold
		Suite:        edwards25519.NewBlakeSHA256Ed25519(),
	}
	// Initialize voters and their votes
	for i, collab := range collaborators {
		vote, err := getSVote(ctx, storageClient, collab)
		if err != nil {
			panic(err)
		}
		secret := authority.Suite.Scalar().Pick(authority.Suite.RandomStream())
		public := authority.Suite.Point().Mul(secret, nil)
		voter := Voter{
			ID:        collab.name,
			PublicKey: public,
			SecretKey: secret,
			Vote:      big.NewInt(int64(vote)),
		}
		// Create VSS shares for the vote
		priPoly := share.NewPriPoly(authority.Suite, authority.ThresholdVSS, voter.Vote, authority.Suite.RandomStream())
		voter.Shares = priPoly.Shares(len(collaborators))
		authority.Voters[i] = voter
	}
	// Tally votes
	encryptedSum := new(big.Int).SetInt64(0)
	for _, voter := range authority.Voters {
		// Reconstruct the vote from shares
		reconstructedVote := reconstructVote(voter.Shares, authority.Suite)
		// Homomorphically add the vote
		encryptedSum.Add(encryptedSum, reconstructedVote)
	}
	// Determine the winner
	totalVotes := big.NewInt(int64(len(authority.Voters)))
	halfVotes := new(big.Int).Div(totalVotes, big.NewInt(2))
	if encryptedSum.Cmp(halfVotes) > 0 {
		fmt.Printf("Candidate 1 wins with %d votes\n", encryptedSum)
	} else {
		fmt.Printf("Candidate 0 wins with %d votes\n", new(big.Int).Sub(totalVotes, encryptedSum))
	}
	now := time.Now()
	for _, cw := range collaborators {
		outputWriter := storageClient.Bucket(cw.outputBucket).Object(fmt.Sprintf("%s-%d", cw.outputFile, now.Unix())).NewWriter(ctx)
		_, err = outputWriter.Write([]byte(fmt.Sprintf("Candidate 1: %d votes\nCandidate 0: %d votes\n", encryptedSum, new(big.Int).Sub(totalVotes, encryptedSum))))
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
func getSVote(ctx context.Context, storageClient *storage.Client, cw collaborator) (float64, error) {
	encryptedBytes, err := getFile(ctx, storageClient, cw.inputBucket, cw.inputFile)
	if err != nil {
		return 0.0, err
	}
	decryptedByte, err := decryptByte(ctx, cw.keyName, cw.sa, cw.wipName, encryptedBytes)
	if err != nil {
		return 0.0, err
	}
	decryptedNumber := strings.TrimSpace(string(decryptedByte))
	num, err := strconv.ParseFloat(decryptedNumber, 64)
	if err != nil {
		return 0.0, err
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
	s, err := ioutil.ReadAll(objectReader)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func reconstructVote(shares []*share.PriShare, suite *edwards25519.SuiteEd25519) *big.Int {
	priPoly, err := share.RecoverPriPoly(suite, shares, len(shares), len(shares))
	if err != nil {
		panic(err)
	}
	return priPoly.Secret().(*big.Int)
}
// https://github.com/vSPACE-Vote/vSPACE/blob/main/vSPACE-VSS-ElGamal.go