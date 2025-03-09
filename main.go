package main

// [Your existing imports and code remain unchanged]
import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// [Your existing variables and structs remain unchanged]
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

func downloadFile(url, outputPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

func readGzFile(fileName string) (*gzip.Reader, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	return gzReader, nil
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func process(url string) ([]map[string]interface{}, error) {
	downloadedFile := "temp_downloaded_file.json.gz"
	if err := downloadFile(url, downloadedFile); err != nil {
		return nil, fmt.Errorf("error downloading file: %v", err)
	}
	defer os.Remove(downloadedFile)

	gzReader, err := readGzFile(downloadedFile)
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

var htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title> MRF VIEWER </title>
    <style>
        #loading-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        #loading-bar-container {
            width: 300px;
            background: #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        #loading-bar {
            width: 0%;
            height: 20px;
            background: #4CAF50;
            transition: width 0.1s linear;
        }
        #loading-text {
            color: white;
            font-family: Arial, sans-serif;
            margin-top: 10px;
            font-size: 16px;
        }
        #download-btn {
            padding: 8px 16px;
            background-color: #2196F3;
            color: white;
            border: none;
            cursor: pointer;
            font-family: Arial, sans-serif;
            margin-top: 10px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container" style="max-width: 1200px; margin: 0 auto; position: relative;">
        <h1 style="font-family: Arial, sans-serif;">MRF VIEWER </h1>
        <form id="url-form">
            <input type="text" id="url-input" placeholder="Enter URL" required style="width: 60%; padding: 8px; margin-right: 10px; font-family: Arial, sans-serif;">
            <button type="submit" id="process-btn" style="padding: 8px 16px; background-color: #4CAF50; color: white; border: none; cursor: pointer; font-family: Arial, sans-serif;">Process</button>
        </form>
        <p id="message" style="margin-top: 10px; color: #333; font-family: Arial, sans-serif;"></p>
        <button id="download-btn" onclick="downloadCSV()">Download as CSV</button>
        <div id="table-container">
            <table id="data-table" style="margin-top: 20px; width: 100%; border-collapse: collapse; overflow-x: auto; display: block; font-family: Arial, sans-serif;"></table>
        </div>
        <div class="pagination" id="pagination" style="margin-top: 20px;"></div>
    </div>

    <div id="loading-overlay">
        <div style="text-align: center;">
            <div id="loading-bar-container">
                <div id="loading-bar"></div>
            </div>
            <div id="loading-text">Loading: 0%</div>
        </div>
    </div>

    <script>
        let allData = [];
        let currentPage = 1;
        const rowsPerPage = 100;
        let filters = {
            NPIs: new Set(),
            InNetworkName: new Set(),
            BillingCode: new Set(),
            Description: new Set(),
            NegotiatedRate: new Set(),
            NegotiatedType: new Set()
        };

        function applyFilters(data) {
            return data.filter(row => {
                const npiString = Array.isArray(row.NPIs) ? row.NPIs.join(';') : String(row.NPIs);
                const rateString = String(row.NegotiatedRate);
                return (
                    (filters.NPIs.size === 0 || filters.NPIs.has(npiString)) &&
                    (filters.InNetworkName.size === 0 || filters.InNetworkName.has(row.InNetworkName)) &&
                    (filters.BillingCode.size === 0 || filters.BillingCode.has(row.BillingCode)) &&
                    (filters.Description.size === 0 || filters.Description.has(row.Description)) &&
                    (filters.NegotiatedRate.size === 0 || filters.NegotiatedRate.has(rateString)) &&
                    (filters.NegotiatedType.size === 0 || filters.NegotiatedType.has(row.NegotiatedType))
                );
            });
        }

        function displayTable(data, page = 1) {
            const table = document.getElementById('data-table');
            table.innerHTML = '';
            const downloadBtn = document.getElementById('download-btn');

            const filteredData = applyFilters(data);
            if (filteredData.length === 0) {
                document.getElementById('message').textContent = 'No data matches the current filters.';
                downloadBtn.style.display = 'none';
                return;
            }

            downloadBtn.style.display = 'block';

            const start = (page - 1) * rowsPerPage;
            const end = Math.min(start + rowsPerPage, filteredData.length);
            const paginatedData = filteredData.slice(start, end);

            const headers = [
                'ReportingEntityName', 'ReportingEntityType', 'LastUpdatedOn', 'Version', 'RootHashID',
                'ProviderGroupID', 'ProviderHashID', 'NPIs', 'TINType', 'TINValue', 'InNetworkName',
                'NegotiationArrangement', 'BillingCodeType', 'BillingCodeTypeVersion', 'BillingCode',
                'Description', 'NegotiatedRate', 'ServiceCodes', 'NegotiatedType', 'ExpirationDate',
                'BillingClass', 'BillingCodeModifiers', 'AdditionalInfo'
            ];
            const filterableColumns = ['NPIs', 'InNetworkName', 'BillingCode', 'Description', 'NegotiatedRate', 'NegotiatedType'];

            const thead = document.createElement('thead');
            const headerRow = document.createElement('tr');
            headers.forEach(header => {
                const th = document.createElement('th');
                th.textContent = header;
                th.style.border = '1px solid #ddd';
                th.style.padding = '8px';
                th.style.textAlign = 'left';
                th.style.maxWidth = '200px';
                th.style.overflow = 'hidden';
                th.style.textOverflow = 'ellipsis';
                th.style.whiteSpace = 'nowrap';
                th.style.backgroundColor = '#f2f2f2';
                th.style.position = 'relative';
                if (filterableColumns.includes(header)) {
                    const filterBtn = document.createElement('button');
                    filterBtn.textContent = '▼';
                    filterBtn.style.marginLeft = '5px';
                    filterBtn.style.padding = '2px 5px';
                    filterBtn.style.cursor = 'pointer';
                    filterBtn.onclick = (e) => toggleFilterDropdown(e, header, filteredData);
                    th.appendChild(filterBtn);
                }
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);

            const tbody = document.createElement('tbody');
            paginatedData.forEach((row, index) => {
                const tr = document.createElement('tr');
                if (index % 2 === 0) {
                    tr.style.backgroundColor = '#f9f9f9';
                }
                headers.forEach(header => {
                    const td = document.createElement('td');
                    const value = row[header];
                    td.textContent = Array.isArray(value) ? value.join(';') : (value !== undefined ? value : '');
                    td.style.border = '1px solid #ddd';
                    td.style.padding = '8px';
                    td.style.textAlign = 'left';
                    td.style.maxWidth = '200px';
                    td.style.overflow = 'hidden';
                    td.style.textOverflow = 'ellipsis';
                    td.style.whiteSpace = 'nowrap';
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);

            updatePagination(filteredData.length, page);
        }

        function toggleFilterDropdown(event, column, data) {
            const existingDropdown = document.querySelector('.filter-dropdown');
            if (existingDropdown) existingDropdown.remove();

            const uniqueValues = new Set(data.map(row => 
                Array.isArray(row[column]) ? row[column].join(';') : String(row[column])
            ));
            const dropdown = document.createElement('div');
            dropdown.className = 'filter-dropdown';
            dropdown.style.position = 'fixed';
            dropdown.style.background = 'white';
            dropdown.style.border = '2px solid #ddd';
            dropdown.style.padding = '20px';
            dropdown.style.zIndex = '1000';
            dropdown.style.minWidth = '400px';
            dropdown.style.maxWidth = '500px';
            dropdown.style.maxHeight = '600px';
            dropdown.style.overflowY = 'auto';
            dropdown.style.fontSize = '18px';
            dropdown.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
            dropdown.style.borderRadius = '8px';

            const buttonRect = event.target.getBoundingClientRect();
            dropdown.style.left = buttonRect.left + 'px';
            dropdown.style.top = (buttonRect.bottom + window.scrollY) + 'px';

            const dropdownRect = dropdown.getBoundingClientRect();
            if (dropdownRect.right > window.innerWidth) {
                dropdown.style.left = (window.innerWidth - dropdownRect.width) + 'px';
            }
            if (dropdownRect.bottom > window.innerHeight) {
                dropdown.style.top = (buttonRect.top + window.scrollY - dropdownRect.height) + 'px';
            }

            uniqueValues.forEach(value => {
                const label = document.createElement('label');
                label.style.display = 'block';
                label.style.marginBottom = '15px';
                label.style.lineHeight = '1.5';
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = filters[column].has(value);
                checkbox.style.marginRight = '15px';
                checkbox.style.transform = 'scale(1.2)';
                checkbox.onchange = () => {
                    if (checkbox.checked) filters[column].add(value);
                    else filters[column].delete(value);
                    currentPage = 1;
                    displayTable(allData, currentPage);
                };
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(" " + value));
                dropdown.appendChild(label);
            });

            document.body.appendChild(dropdown);
            event.stopPropagation();
            document.addEventListener('click', closeDropdown);
        }

        function closeDropdown(event) {
            const dropdown = document.querySelector('.filter-dropdown');
            if (dropdown && !dropdown.contains(event.target)) {
                dropdown.remove();
                document.removeEventListener('click', closeDropdown);
            }
        }

        function updatePagination(totalRows, page) {
            const pagination = document.getElementById('pagination');
            pagination.innerHTML = '';

            const totalPages = Math.ceil(totalRows / rowsPerPage);
            currentPage = Math.min(page, totalPages) || 1;

            const prevBtn = document.createElement('button');
            prevBtn.textContent = 'Previous';
            prevBtn.disabled = currentPage === 1;
            prevBtn.style.padding = '8px 16px';
            prevBtn.style.backgroundColor = currentPage === 1 ? '#cccccc' : '#4CAF50';
            prevBtn.style.color = 'white';
            prevBtn.style.border = 'none';
            prevBtn.style.cursor = currentPage === 1 ? 'not-allowed' : 'pointer';
            prevBtn.style.margin = '0 5px';
            prevBtn.onclick = () => displayTable(allData, currentPage - 1);
            pagination.appendChild(prevBtn);

            for (let i = 1; i <= totalPages; i++) {
                const btn = document.createElement('button');
                btn.textContent = i;
                btn.style.padding = '8px 16px';
                btn.style.backgroundColor = i === currentPage ? '#4CAF50' : '#f2f2f2';
                btn.style.color = i === currentPage ? 'white' : '#333';
                btn.style.border = 'none';
                btn.style.cursor = 'pointer';
                btn.style.margin = '0 5px';
                btn.onclick = () => displayTable(allData, i);
                pagination.appendChild(btn);
            }

            const nextBtn = document.createElement('button');
            nextBtn.textContent = 'Next';
            nextBtn.disabled = currentPage === totalPages;
            nextBtn.style.padding = '8px 16px';
            nextBtn.style.backgroundColor = currentPage === totalPages ? '#cccccc' : '#4CAF50';
            nextBtn.style.color = 'white';
            nextBtn.style.border = 'none';
            nextBtn.style.cursor = currentPage === totalPages ? 'not-allowed' : 'pointer';
            nextBtn.style.margin = '0 5px';
            nextBtn.onclick = () => displayTable(allData, currentPage + 1);
            pagination.appendChild(nextBtn);
        }

        function showLoading() {
            const overlay = document.getElementById('loading-overlay');
            const bar = document.getElementById('loading-bar');
            const text = document.getElementById('loading-text');
            overlay.style.display = 'flex';
            bar.style.width = '0%';
            text.textContent = 'Loading: 0%';

            let progress = 0;
            const interval = setInterval(() => {
                if (progress < 90) {
                    progress += 1;
                    bar.style.width = progress + '%';
                    text.textContent = 'Loading: ' + progress + '%';
                }
            }, 50);

            return () => {
                clearInterval(interval);
                bar.style.width = '100%';
                text.textContent = 'Loading: 100%';
                setTimeout(() => overlay.style.display = 'none', 300);
            };
        }

        function downloadCSV() {
            const headers = [
                'ReportingEntityName', 'ReportingEntityType', 'LastUpdatedOn', 'Version', 'RootHashID',
                'ProviderGroupID', 'ProviderHashID', 'NPIs', 'TINType', 'TINValue', 'InNetworkName',
                'NegotiationArrangement', 'BillingCodeType', 'BillingCodeTypeVersion', 'BillingCode',
                'Description', 'NegotiatedRate', 'ServiceCodes', 'NegotiatedType', 'ExpirationDate',
                'BillingClass', 'BillingCodeModifiers', 'AdditionalInfo'
            ];

            const escapeCSV = (value) => {
                if (value === undefined || value === null) return '';
                const str = String(value);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return '"' + str.replace(/"/g, '""') + '"';
                }
                return str;
            };

            let csvContent = headers.join(',') + '\n';
            allData.forEach(row => {
                const rowValues = headers.map(header => {
                    const value = row[header];
                    return Array.isArray(value) ? escapeCSV(value.join(';')) : escapeCSV(value);
                });
                csvContent += rowValues.join(',') + '\n';
            });

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'healthcare_data.csv');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        document.getElementById('url-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('url-input').value;
            const processBtn = document.getElementById('process-btn');
            const message = document.getElementById('message');

            processBtn.disabled = true;
            processBtn.style.backgroundColor = '#cccccc';
            processBtn.style.cursor = 'not-allowed';
            processBtn.textContent = 'Processing...';
            message.textContent = '';

            const hideLoading = showLoading();

            try {
                const response = await fetch('/api/process', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                if (!response.ok) throw new Error('Network response was not ok');
                const result = await response.json();
                allData = result.data;
                displayTable(allData, 1);
                message.textContent = result.message;
            } catch (error) {
                message.textContent = 'Error: ' + error.message;
            } finally {
                hideLoading();
                processBtn.disabled = false;
                processBtn.style.backgroundColor = '#4CAF50';
                processBtn.style.cursor = 'pointer';
                processBtn.textContent = 'Process';
            }
        });
    </script>
</body>
</html>
`

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        tmpl, err := template.New("index").Parse(htmlTemplate)
        if err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            log.Printf("Template parsing error: %v", err)
            return
        }
        if err := tmpl.Execute(w, nil); err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            log.Printf("Template execution error: %v", err)
        }
    })

    http.HandleFunc("/api/process", func(w http.ResponseWriter, r *http.Request) {
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
    })

    // Updated to use the PORT environment variable for Render
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080" // Default for local testing
    }
    log.Println("Server starting on :" + port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}