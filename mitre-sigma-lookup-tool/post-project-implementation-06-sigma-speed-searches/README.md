## Post Project Implmentation #6: Improving the speed of Sigma searches
- This implementation was all about improving the speed of the Sigma searches. Currently, everytime someone searched for an ATT&CK technique such as `T1566`, the program opened every Sigma file, read the file contents, searched for the technique, parsed the YAML/JSON metadata and returned the matches. If someone searched another technique, it repeated this entire process again. Therefore, if we have 10,000 Sigma rules and a 100 ATT&CK techniques to process, this could mean reading 10,000 files 100 times.
- Therefore, the solution to this is to use an inverted index data structure using a Python dictionary combined with an initialization cache. In general, an Inverted Index maps a search term (the ATT&CK ID) directly to the files that contain it, similar to the index at the back of a textbook

- After the changes, the idea is for the program to scan all Sigma files once, extract every ATT&CK ID it finds and essentially build a lookup table (dictionary) in memory. Conceptually, it creates something like this

  ```python
  SIGMA_INDEX = {
      "T1566": [
          {"file": "rule1.yml", "title": "Phishing Detection"},
          {"file": "rule2.yml", "title": "Email Attachment Alert"}
      ],
      "T1036": [
          {"file": "rule3.yml", "title": "Masquerading Detection"}
      ]
  }
  ```
- Later, when someone searches for `T1566`, the program does `SIGMA_INDEX["T1566"]` instead of searching the entire disk again. This reduces the search operation from a full file scan to an average case `O(1)` dictionary lookup
 
## Code Explanation
- First, I created a global dictionary that holds all ATT&CK to rule mappings

  ```python
  SIGMA_INDEX = {}
  ```
  
- This function scans all Sigma rules once during startup and creates a lookup table in memory. Instead of re-reading thousands of files for every ATT&CK technique search, the program reuses this cached data throughout report processing. This reduces disk I/O and allows techniques to be retrieved through fast dictionary lookups

  ```python
  build_sigma_index()
  ```

- This function performs a direct lookup against the cached Sigma index and returns the matching rules for a given ATT&CK technique

  ```python
  lookup_sigma_in_index()
  ```
  
- Together, these changes eliminate repeated disk scans and metadata parsing, significantly reducing the time required to process large numbers of ATT&CK techniques against large Sigma rule repositories

## Performance Comparison Table
- I compared both the scripts (the original code which did not have an inverted index data structure and the enchanced one which did have one). I used Python's `import time` library to see how much time it takes to generate the results. Below are my findings

| ATT&CK IDs | Old Implementation | New Implementation |  |  |
|-----------:|-------------------:|-------------------:|-------------------:|-------------------:|
|            | Search Time (s) | Index Build (s) | Query Lookup (s) | Total Search Time (Index Build + Query Lookup) (s) |
| 5 (Test 1) | 7.1710 | 4.8911 | 0.7852 | 5.6763 |
| 5 (Test 2) | 7.6973 | 4.8720 | 0.8080 | 5.6799 |
| 5 (Test 3) | 7.3689 | 4.9268 | 0.8379 | 5.7647 |
| 10 | 14.2408 | 4.8889 | 1.3753 | 6.2642 |
| 50 | 65.0105 | 4.9635 | 6.4504 | 11.4139 |
| 100 | 126.3140 | 4.9363 | 12.9058 | 17.8422 |

- We note that the original implementation's time complexity was `O(N * M)` where for every technique `N`, the program searched for all available files, `M` items. As either grows, the runtime increases rapidly because the same data is repeatedly scanned

- The enhanced approach is split into two phases where it builds the index once, `O(M)` time and then performs the lookup where each query becomes a direct dictionary/hash-table lookup, `O(1)` and for `N` queries it is, `O(N)` and so the total time complexity becomes `O(M + N)`. The original design repeatedly scans the entire dataset for every query `O(N * M)` whereas the enhanced design scans the dataset only once and then performs constant-time lookups `O(M + N)`. This is a trade-off where we spend extra memory to build an index, allowing us to replace repeated expensive searches with very fast lookups

## Performance Comparison Demo
Original Implementation
  - Note: Refresh the page if the bottom two videos do not load

https://github.com/user-attachments/assets/454be4ee-ed8e-49f0-a785-31c9f2040851

Enchanced Implementation

https://github.com/user-attachments/assets/272c4ffc-9834-4fff-abf3-73ac47ea3c16

