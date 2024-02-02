# G45_Major-Project_Cybersecurity

## Cyber Security Reconnaissance and Vulnerability Assessment

The provided code creates a Graphical User Interface (GUI) for a security assessment tool named "ReconVuln Software." This tool leverages the tkinter library to build the GUI and integrates functionalities for conducting security assessments and vulnerability analysis.

### Code Structure Overview:

- Essential modules are imported from the tkinter library and other dependencies (e.g., requests, Wappalyzer, and webbrowser).
- A list of options for the search functionality is defined.
- The core functionality is encapsulated in the `SecurityAssessmentGUI` class, representing the GUI window.

### Reconnaissance Tab:

The `create_recon_tab` method generates a dedicated tab for reconnaissance tasks, including sections for IP lookup, website analysis with Wappalyzer, and utilizing the Google Dork search engine. GUI elements are set up and linked to corresponding functions for task execution.

The `update_input_fields` method dynamically updates input fields based on the selected search option, showing or hiding fields accordingly.

Specific security assessments are conducted by methods such as `perform_ip_lookup`, `analyze_website`, `analyze_with_categories`, and `analyze_with_versions_and_categories`. External libraries and APIs are employed for retrieving and analyzing information related to IP addresses and websites.

The `search_google_dorks` method performs a Google Dork search based on user-selected options and query, constructing the appropriate search query and opening results in a new browser tab.

### Vulnerability Assessment Tab:

The `create_vulnerability_tab` method generates a tab for vulnerability assessment, with sections for network security, system security, and data security. Radio buttons are provided for each assessment item, enabling user selection.

### Summary:

In summary, this code provides a user-friendly interface for conducting security assessments and vulnerability analysis. It incorporates diverse tools and techniques to offer an efficient and comprehensive assessment of security aspects.
