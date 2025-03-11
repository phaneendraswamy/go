package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

var codesToKeep = []string{
	"81416", "81552", "81519", "81521", "81522", "81541", "81518", "81542",
	"0045U", "0047U", "81540", "0172U", "81546", "0080U", "0037U", "81595",
	"81525", "0018U", "81455", "81538", "81442", "81551", "81408", "0090U",
	"81162", "81411", "81493", "81407", "81185", "81490", "81201", "0013M",
	"81450", "0012M", "0089U", "81539", "0005U", "81503", "81432", "81317",
	"81445", "81238", "81321", "81439", "81413", "81414", "81435", "81436",
	"81528", "81410", "0003M", "81212", "81433", "87633", "87507", "81405",
	"81266", "81406", "81307", "81161", "81404", "81286", "87902", "81300",
	"87632", "81319", "81203", "81403", "81267", "81315", "81294", "81342",
	"81269", "81261", "81276", "81275", "81120", "81327", "0154U", "81208",
	"81297", "81340", "81375", "81268", "81500", "81313", "0023U", "81310",
	"81218", "81350", "81265", "81308", "81323", "81170", "81263", "81311",
	"81121", "81306", "81225", "81292", "81175", "81298", "81422", "81249",
	"81434", "81448", "81164", "81425", "81220", "81302", "81223", "81163",
	"81226", "81437", "81438", "81222", "81295", "81217", "81215", "0033U",
	"81301", "81378", "81379", "81272", "81314", "81334", "81235", "81460",
	"81229", "81465", "81420", "81507", "0327U", "81415", "81440", "0115U",
	"87483", "0225U", "87801", "87631", "87481", "0242U", "81529", "0118U",
	"81479", "U0003", "0239U", "0340U", "U0002", "U0001", "U0004", "U0005",
}

type RootData struct {
	ReportingEntityName string        `json:"reporting_entity_name"`
	ReportingEntityType string        `json:"reporting_entity_type"`
	Version             string        `json:"version"`
	LastUpdatedOn       string        `json:"last_updated_on"`
	InNetwork           []interface{} `json:"in_network"`
	ProviderReferences  []interface{} `json:"provider_references,omitempty"`
}

type ProviderGroup struct {
	NPI []int `json:"npi"`
	TIN struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"tin"`
}

type NegotiatedPrice struct {
	NegotiatedRate      float64  `json:"negotiated_rate"`
	ServiceCode         []string `json:"service_code"`
	NegotiatedType      string   `json:"negotiated_type"`
	ExpirationDate      string   `json:"expiration_date"`
	BillingClass        string   `json:"billing_class"`
	BillingCodeModifier []string `json:"billing_code_modifier"`
	AdditionalInfo      string   `json:"additional_information,omitempty"`
}

type NegotiatedRate struct {
	NegotiatedPrices   []NegotiatedPrice `json:"negotiated_prices"`
	ProviderGroups     []ProviderGroup   `json:"provider_groups,omitempty"`
	ProviderReferences []interface{}     `json:"provider_references,omitempty"`
}

type InNetwork struct {
	NegotiationArrangement string           `json:"negotiation_arrangement"`
	Name                   string           `json:"name"`
	BillingCodeType        string           `json:"billing_code_type"`
	BillingCodeTypeVersion string           `json:"billing_code_type_version"`
	BillingCode            string           `json:"billing_code"`
	Description            string           `json:"description"`
	NegotiatedRates        []NegotiatedRate `json:"negotiated_rates"`
}

func createHashID(value string) string {
	hash := sha256.New()
	hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil))
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func worker(id int, jobs <-chan interface{}, results chan<- []map[string]interface{}, wg *sync.WaitGroup, root RootData, providerReferences []interface{}, isCentene bool) {
	defer wg.Done()
	for job := range jobs {
		var standardizedData []map[string]interface{}
		var err error

		if isCentene {
			inNetworkBytes, _ := json.Marshal(job)
			var inNetwork InNetwork
			if err := json.Unmarshal(inNetworkBytes, &inNetwork); err != nil {
				log.Printf("Worker %d: Error converting to InNetwork: %v", id, err)
				continue
			}
			standardizedData, err = standardizeToCentene(inNetwork, root)
		} else {
			inNetworkMap, ok := job.(map[string]interface{})
			if !ok {
				log.Printf("Worker %d: Error: job is not a map[string]interface{}", id)
				continue
			}
			rootHashID := createHashID(root.ReportingEntityName + root.ReportingEntityType + root.LastUpdatedOn)
			standardizedData, err = standardizeToAetna(inNetworkMap, rootHashID, root.ReportingEntityName, root.ReportingEntityType, root.LastUpdatedOn, root.Version, providerReferences)
		}

		if err != nil {
			log.Printf("Worker %d: Error: %v", id, err)
			continue
		}
		if len(standardizedData) > 0 {
			results <- standardizedData
		}
	}
}

func standardizeToAetna(inNetworkMap map[string]interface{}, rootHashID, root, rootType, lastUpdated, version string, providerReferences []interface{}) ([]map[string]interface{}, error) {
	var standardizedData []map[string]interface{}

	negotiatedRates, ok := inNetworkMap["negotiated_rates"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("negotiated_rates is missing or not an array")
	}

	name, _ := inNetworkMap["name"].(string)
	negotiationArrangement, _ := inNetworkMap["negotiation_arrangement"].(string)
	billingCodeType, _ := inNetworkMap["billing_code_type"].(string)
	billingCodeTypeVersion, _ := inNetworkMap["billing_code_type_version"].(string)
	description, _ := inNetworkMap["description"].(string)
	billingCode, _ := inNetworkMap["billing_code"].(string)

	if !contains(codesToKeep, billingCode) {
		return standardizedData, nil
	}

	for _, rate := range negotiatedRates {
		rateMap := rate.(map[string]interface{})
		prices := rateMap["negotiated_prices"].([]interface{})

		var providerGroupIDs []interface{}
		if pgids, ok := rateMap["provider_references"].([]interface{}); ok {
			providerGroupIDs = pgids
		} else if pgid, ok := rateMap["provider_references"]; ok {
			providerGroupIDs = []interface{}{pgid}
		}

		for _, price := range prices {
			priceMap := price.(map[string]interface{})
			serviceCodes := []string{}
			if sc, ok := priceMap["service_code"].([]interface{}); ok {
				for _, s := range sc {
					serviceCodes = append(serviceCodes, s.(string))
				}
			}

			negotiatedType, _ := priceMap["negotiated_type"].(string)
			expirationDate, _ := priceMap["expiration_date"].(string)
			billingClass, _ := priceMap["billing_class"].(string)
			billingCodeModifiers := []string{}
			if bcm, ok := priceMap["billing_code_modifier"].([]interface{}); ok {
				for _, m := range bcm {
					billingCodeModifiers = append(billingCodeModifiers, m.(string))
				}
			}
			additionalInfo, _ := priceMap["additional_information"].(string)

			providerGroupID := 0.0
			providerHashID := ""
			npis := []int{}
			tinType := ""
			tinValue := ""

			if len(providerGroupIDs) > 0 {
				var pgidFloat float64
				switch pgid := providerGroupIDs[0].(type) {
				case float64:
					pgidFloat = pgid
				case int:
					pgidFloat = float64(pgid)
				case string:
					if n, err := fmt.Sscanf(pgid, "%f", &pgidFloat); err != nil || n != 1 {
						continue
					}
				}

				providerGroupID = pgidFloat
				for _, ref := range providerReferences {
					refMap := ref.(map[string]interface{})
					var refIDFloat float64
					switch refID := refMap["provider_group_id"].(type) {
					case float64:
						refIDFloat = refID
					case int:
						refIDFloat = float64(refID)
					case string:
						if n, err := fmt.Sscanf(refID, "%f", &refIDFloat); err != nil || n != 1 {
							continue
						}
					}
					if refIDFloat == pgidFloat {
						providerHashID = createHashID(fmt.Sprintf("%v", refIDFloat))
						if providerGroups, ok := refMap["provider_groups"].([]interface{}); ok {
							for _, pg := range providerGroups {
								pgMap := pg.(map[string]interface{})
								if npisArr, ok := pgMap["npi"].([]interface{}); ok {
									for _, npi := range npisArr {
										switch n := npi.(type) {
										case float64:
											npis = append(npis, int(n))
										case int:
											npis = append(npis, n)
										case string:
											var npiInt int
											if n, err := fmt.Sscanf(n, "%d", &npiInt); err == nil && n == 1 {
												npis = append(npis, npiInt)
											}
										}
									}
								}
								if tin, ok := pgMap["tin"].(map[string]interface{}); ok {
									tinType, _ = tin["type"].(string)
									tinValue, _ = tin["value"].(string)
								}
							}
						}
						break
					}
				}
			}

			standardizedData = append(standardizedData, map[string]interface{}{
				"ReportingEntityName":    root,
				"ReportingEntityType":    rootType,
				"LastUpdatedOn":          lastUpdated,
				"Version":                version,
				"RootHashID":             rootHashID,
				"ProviderGroupID":        providerGroupID,
				"ProviderHashID":         providerHashID,
				"NPIs":                   npis,
				"TINType":                tinType,
				"TINValue":               tinValue,
				"InNetworkName":          name,
				"NegotiationArrangement": negotiationArrangement,
				"BillingCodeType":        billingCodeType,
				"BillingCodeTypeVersion": billingCodeTypeVersion,
				"BillingCode":            billingCode,
				"Description":            description,
				"NegotiatedRate":         priceMap["negotiated_rate"].(float64),
				"ServiceCodes":           serviceCodes,
				"NegotiatedType":         negotiatedType,
				"ExpirationDate":         expirationDate,
				"BillingClass":           billingClass,
				"BillingCodeModifiers":   billingCodeModifiers,
				"AdditionalInfo":         additionalInfo,
			})
		}
	}
	return standardizedData, nil
}

func standardizeToCentene(inNetwork InNetwork, root RootData) ([]map[string]interface{}, error) {
	var standardizedData []map[string]interface{}

	if !contains(codesToKeep, inNetwork.BillingCode) {
		return standardizedData, nil
	}

	rootHashID := createHashID(root.ReportingEntityName + root.ReportingEntityType + root.LastUpdatedOn)

	for _, rate := range inNetwork.NegotiatedRates {
		for _, price := range rate.NegotiatedPrices {
			for _, pg := range rate.ProviderGroups {
				standardizedData = append(standardizedData, map[string]interface{}{
					"ReportingEntityName":    root.ReportingEntityName,
					"ReportingEntityType":    root.ReportingEntityType,
					"LastUpdatedOn":          root.LastUpdatedOn,
					"Version":                root.Version,
					"RootHashID":             rootHashID,
					"ProviderGroupID":        0.0,
					"ProviderHashID":         "",
					"NPIs":                   pg.NPI,
					"TINType":                pg.TIN.Type,
					"TINValue":               pg.TIN.Value,
					"InNetworkName":          inNetwork.Name,
					"NegotiationArrangement": inNetwork.NegotiationArrangement,
					"BillingCodeType":        inNetwork.BillingCodeType,
					"BillingCodeTypeVersion": inNetwork.BillingCodeTypeVersion,
					"BillingCode":            inNetwork.BillingCode,
					"Description":            inNetwork.Description,
					"NegotiatedRate":         price.NegotiatedRate,
					"ServiceCodes":           price.ServiceCode,
					"NegotiatedType":         price.NegotiatedType,
					"ExpirationDate":         price.ExpirationDate,
					"BillingClass":           price.BillingClass,
					"BillingCodeModifiers":   price.BillingCodeModifier,
					"AdditionalInfo":         "",
				})
			}
		}
	}
	return standardizedData, nil
}

func process(url string) ([]map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error downloading file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error decompressing file: %v", err)
	}
	defer gzReader.Close()

	var rootData RootData
	if err := json.NewDecoder(gzReader).Decode(&rootData); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	isCentene := strings.Contains(strings.ToLower(rootData.ReportingEntityName), "centene") ||
		strings.Contains(strings.ToLower(rootData.ReportingEntityName), "bluecross blueshield of tennessee") ||
		len(rootData.ProviderReferences) == 0

	numWorkers := 3
	jobs := make(chan interface{}, numWorkers)
	results := make(chan []map[string]interface{}, numWorkers)
	var wg sync.WaitGroup

	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg, rootData, rootData.ProviderReferences, isCentene)
	}

	go func() {
		for _, inNetwork := range rootData.InNetwork {
			jobs <- inNetwork
		}
		close(jobs)
	}()

	resultsByCode := make(map[string][]map[string]interface{})
	for _, code := range codesToKeep {
		resultsByCode[code] = []map[string]interface{}{}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		for _, entry := range result {
			billingCode, ok := entry["BillingCode"].(string)
			if !ok {
				continue
			}
			if contains(codesToKeep, billingCode) && len(resultsByCode[billingCode]) < 100 {
				resultsByCode[billingCode] = append(resultsByCode[billingCode], entry)
			}
		}
	}

	var allResults []map[string]interface{}
	for _, code := range codesToKeep {
		allResults = append(allResults, resultsByCode[code]...)
	}

	return allResults, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		http.Error(w, "Bad Request: URL is required", http.StatusBadRequest)
		return
	}

	results, err := process(req.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error processing URL: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Data    []map[string]interface{} `json:"data"`
		Total   int                      `json:"total"`
		Message string                   `json:"message"`
	}{
		Data:    results,
		Total:   len(results),
		Message: fmt.Sprintf("Displaying up to 100 entries per billing code, total %d entries", len(results)),
	})
}

func main() {
	http.HandleFunc("/api/process", handler)
	log.Println("Handler registered for /api/process")
}