"""
Created by 'Vijay Nath Shukla' on May 20, 2023. Contact: vijayshukla8416@gmail.com

The code creates a user-friendly interface for performing security assessments and
gathering information related to website analysis and vulnerabilities.

This code was developed for a Computer Science Major Project completed last year.
"""

import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import tkinter.filedialog
from tkinter.font import Font
import requests
from Wappalyzer import Wappalyzer, WebPage
import webbrowser

OPTIONS = [
    "Site-specific search",
    "File type search",
    "Directory listing",
    "Login pages",
    "Vulnerable applications",
    "Information disclosure"
]

class SecurityAssessmentGUI:
    def __init__(self, window):
        self.window = window
        self.window.title("ReconVuln Software")
        self.window.geometry('1000x500')
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill='both', expand=True)
        self.create_vulnerability_tab()
        self.create_recon_tab()
        self.create_menu()
        self.update_input_fields()

    def create_recon_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Reconnaissance")
        container = ttk.Frame(tab)
        container.pack(fill='both', expand=True)
        self.option_var = tk.StringVar(container)

        # Shodan IP Lookup
         # Create IP lookup section (Container 1)
        frame1 = ttk.Frame(container, borderwidth=2, relief="solid")
        frame1.pack(side='left', fill='both', expand=True)
        label_ip = ttk.Label(frame1, text="IP Address:")
        label_ip.pack(padx=20, pady=20)
        entry_ip = ttk.Entry(frame1, width=30)
        entry_ip.pack(padx=20, pady=5)
        button_lookup = ttk.Button(frame1, text="Perform IP Lookup",
                                   command=lambda: self.perform_ip_lookup(entry_ip.get()))
        button_lookup.pack(padx=20, pady=20)

        # Wappalyzer website analysis
         # Create website analysis section (Container 2)
        frame2 = ttk.Frame(container, borderwidth=2, relief="solid")
        frame2.pack(side='left', fill='both', expand=True)
        label_url = ttk.Label(frame2, text="URL:")
        label_url.pack(padx=20, pady=20)
        entry_url = ttk.Entry(frame2, width=30)
        entry_url.pack(padx=20, pady=5)
        button_analyze = ttk.Button(frame2, text="Analyze Website",
                                    command=lambda: self.analyze_website(entry_url.get()))
        button_analyze.pack(padx=20, pady=10)
        button_analyze_categories = ttk.Button(frame2, text="Analyze with Categories",
                                               command=lambda: self.analyze_with_categories(entry_url.get()))
        button_analyze_categories.pack(padx=20, pady=10)
        button_analyze_versions = ttk.Button(frame2, text="Analyze with Versions and Categories",
                                             command=lambda: self.analyze_with_versions_and_categories(entry_url.get()))
        button_analyze_versions.pack(padx=20, pady=10)

        # Google dork search engine
         # Search option selection
        self.option_var = tk.StringVar(container)
        self.option_var.set(OPTIONS[0])
        option_menu = tk.OptionMenu(container, self.option_var, *OPTIONS)
        option_menu.pack(pady=20)

         # Search query input
        label_query = tk.Label(container, text="Search Query:")
        label_query.pack()
        self.entry_query = tk.Entry(container, width=30)
        self.entry_query.pack(pady=5)

         # Additional input fields for specific search options
        self.entry_file_type = tk.Entry(container, width=10)
        self.entry_application = tk.Entry(container, width=20)

         # Button to initiate the search
        button_search = tk.Button(container, text="Search", command=self.search_google_dorks)
        button_search.pack(pady=20)

    def update_input_fields(self):
        selected_option = self.option_var.get()
        if selected_option == "File type search":
            self.entry_file_type.pack()
            self.entry_application.pack_forget()
        elif selected_option == "Vulnerable applications":
            self.entry_file_type.pack_forget()
            self.entry_application.pack()
        else:
            self.entry_file_type.pack_forget()
            self.entry_application.pack_forget()

    def perform_ip_lookup(self, ip_address):
        try:
            # Make a request to the InternetDB API
            url = f"https://internetdb.shodan.io/{ip_address}"
            response = requests.get(url)
            data = response.json()

            # Display the response data in a message box
            messagebox.showinfo("IP Lookup Results", data)

        except requests.RequestException as e:
            messagebox.showerror("Request Error", str(e))
        except ValueError as e:
            messagebox.showerror("Response Error", str(e))

    def analyze_website(self, url):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()

        try:
            results = wappalyzer.analyze(webpage)
            messagebox.showinfo("Website Analysis", f"Wappalyzer Results: {results}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during website analysis: {str(e)}")

    def analyze_with_categories(self, url):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()

        try:
            results = wappalyzer.analyze_with_categories(webpage)
            messagebox.showinfo("Website Analysis", f"Wappalyzer Results with Categories: {results}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during website analysis: {str(e)}")

    def analyze_with_versions_and_categories(self, url):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()

        try:
            results = wappalyzer.analyze_with_versions_and_categories(webpage)
            messagebox.showinfo("Website Analysis", f"Wappalyzer Results with Versions and Categories: {results}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during website analysis: {str(e)}")

    def search_google_dorks(self):
        selected_option = self.option_var.get()
        search_query = self.entry_query.get()

        if selected_option == "Site-specific search":
            query = f"site:{search_query}"
        elif selected_option == "File type search":
            file_type = self.entry_file_type.get()
            query = f"filetype:{file_type} {search_query}"
        elif selected_option == "Directory listing":
            query = f"intitle:index.of {search_query}"
        elif selected_option == "Login pages":
            query = f"intitle:login {search_query}"
        elif selected_option == "Vulnerable applications":
            application = self.entry_application.get()
            query = f"{application} {search_query}"
        elif selected_option == "Information disclosure":
            query = f"intitle:index.of {search_query}"

        # Perform the Google search and display the results
        messagebox.showinfo("Google Dork Search", f"Performing search with query: {query}")

        search_url = f"https://www.google.com/search?q={query}"
        webbrowser.open_new_tab(search_url)

    def create_vulnerability_tab(self):
        # variable defined
        self.firewall_var = tk.StringVar()
        self.segmentation_var = tk.StringVar()
        self.ids_ips_var = tk.StringVar()
        self.encryption_var = tk.StringVar()
        self.patching_var = tk.StringVar()
        self.password_policy_var = tk.StringVar()
        self.admin_privileges_var = tk.StringVar()
        self.anti_malware_var = tk.StringVar()
        self.access_control_var = tk.StringVar()
        self.data_encryption_var = tk.StringVar()
        self.data_backup_var = tk.StringVar()
        self.data_retention_var = tk.StringVar()
        self.physical_access_var = tk.StringVar()
        self.cctv_var = tk.StringVar()
        self.security_guards_var = tk.StringVar()
        self.biometric_access_var = tk.StringVar()
        self.security_awareness_var = tk.StringVar()
        self.password_best_practices_var = tk.StringVar()
        self.phishing_training_var = tk.StringVar()
        self.data_handling_var = tk.StringVar()
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Vulnerability Assessment")
        self.text_widget = tk.Text(tab, wrap=tk.WORD)

        #font of tab title
        style = ttk.Style()
        style.configure("TNotebook.Tab", font=("Arial", 12))

        # Create a scrollbar
        scrollbar = tk.Scrollbar(tab)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a text widget and associate the scrollbar with it
        text_widget = tk.Text(tab, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(fill='both', expand=True)
        scrollbar.config(command=text_widget.yview)

        # Create a Custom Font
        radio_font = Font(family="Arial", size=11)
        text_widget.tag_configure("custom_tag", font=("Arial", 13, "bold"), foreground="green")

        # Network Security
        text_widget.insert(tk.END, "NETWORK SECURITY\n", "custom_tag")
        text_widget.insert(tk.END, "1. Are firewalls implemented to control network traffic?\n")
        option_firewall1 = tk.Radiobutton(tab, text="Yes", variable=self.firewall_var, value="Yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_firewall1)
        text_widget.insert(tk.END, "\n")
        option_firewall2 = tk.Radiobutton(tab, text="No", variable=self.firewall_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_firewall2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "2. Is network segmentation utilized?\n")
        option_segmentation_var1 = tk.Radiobutton(tab, text="Yes", variable=self.segmentation_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_segmentation_var1)
        text_widget.insert(tk.END, "\n")
        option_segmentation_var2 = tk.Radiobutton(tab, text="No", variable=self.segmentation_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_segmentation_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "3. Are intrusion detection/prevention systems deployed?\n")
        option_ids_ips_var1 = tk.Radiobutton(tab, text="Yes", variable=self.ids_ips_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_ids_ips_var1)
        text_widget.insert(tk.END, "\n")
        option_ids_ips_var2 = tk.Radiobutton(tab, text="No", variable=self.ids_ips_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_ids_ips_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "4. Is encryption used for network communications?\n")
        option_encryption_var1 = tk.Radiobutton(tab, text="Yes", variable=self.encryption_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_encryption_var1)
        text_widget.insert(tk.END, "\n")
        option_encryption_var2 = tk.Radiobutton(tab, text="No", variable=self.encryption_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_encryption_var2)
        text_widget.insert(tk.END, "\n")

        # System Security
        text_widget.insert(tk.END, "\nSYSTEM SECURITY\n", "custom_tag")
        text_widget.insert(tk.END, "5. Are operating systems and software applications regularly patched and updated?\n")
        option_patching_var1 = tk.Radiobutton(tab, text="Yes", variable=self.patching_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_patching_var1)
        text_widget.insert(tk.END, "\n")
        option_patching_var2 = tk.Radiobutton(tab, text="No", variable=self.patching_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_patching_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "6. Is there a strong password policy in place?\n")
        option_password_policy_var1 = tk.Radiobutton(tab, text="Yes", variable=self.password_policy_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_password_policy_var1)
        text_widget.insert(tk.END, "\n")
        option_password_policy_var2 = tk.Radiobutton(tab, text="No", variable=self.password_policy_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_password_policy_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "7. Are administrative privileges properly managed?\n")
        option_admin_privileges_var1 = tk.Radiobutton(tab, text="Yes", variable=self.admin_privileges_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_admin_privileges_var1)
        text_widget.insert(tk.END, "\n")
        option_admin_privileges_var2 = tk.Radiobutton(tab, text="No", variable=self.admin_privileges_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_admin_privileges_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "8. Is anti-malware software installed and up to date on all systems?\n")
        option_anti_malware_var1 = tk.Radiobutton(tab, text="Yes", variable=self.anti_malware_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_anti_malware_var1)
        text_widget.insert(tk.END, "\n")
        option_anti_malware_var2 = tk.Radiobutton(tab, text="No", variable=self.anti_malware_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_anti_malware_var2)
        text_widget.insert(tk.END, "\n")

        # Data Security
        text_widget.insert(tk.END, "\nDATA SECURITY\n", "custom_tag")
        text_widget.insert(tk.END, "9. Is access control implemented to restrict unauthorized data access?\n")
        option_access_control_var1 = tk.Radiobutton(tab, text="Yes", variable=self.access_control_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_access_control_var1)
        text_widget.insert(tk.END, "\n")
        option_access_control_var2 = tk.Radiobutton(tab, text="No", variable=self.access_control_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_access_control_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "10. Is sensitive data encrypted in storage and during transmission?\n")
        option_data_encryption_var1 = tk.Radiobutton(tab, text="Yes", variable=self.data_encryption_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_encryption_var1)
        text_widget.insert(tk.END, "\n")
        option_data_encryption_var2 = tk.Radiobutton(tab, text="No", variable=self.data_encryption_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_encryption_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "11. Is regular data backup performed to prevent data loss?\n")
        option_data_backup_var1 = tk.Radiobutton(tab, text="Yes", variable=self.data_backup_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_backup_var1)
        text_widget.insert(tk.END, "\n")
        option_data_backup_var2 = tk.Radiobutton(tab, text="No", variable=self.data_backup_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_backup_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "12. Is there a data retention policy in place?\n")
        option_data_retention_var1 = tk.Radiobutton(tab, text="Yes", variable=self.data_retention_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_retention_var1)
        text_widget.insert(tk.END, "\n")
        option_data_retention_var2 = tk.Radiobutton(tab, text="No", variable=self.data_retention_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_retention_var2)
        text_widget.insert(tk.END, "\n")

        # Physical Security
        text_widget.insert(tk.END, "\nPHYSICAL SECURITY\n", "custom_tag")
        text_widget.insert(tk.END, "13. Is there controlled access to physical facilities?\n")
        option_physical_access_var1 = tk.Radiobutton(tab, text="Yes", variable=self.physical_access_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_physical_access_var1)
        text_widget.insert(tk.END, "\n")
        option_physical_access_var2 = tk.Radiobutton(tab, text="No", variable=self.physical_access_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_physical_access_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "14. Are CCTV cameras installed to monitor key areas?\n")
        option_cctv_var1 = tk.Radiobutton(tab, text="Yes", variable=self.cctv_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_cctv_var1)
        text_widget.insert(tk.END, "\n")
        option_cctv_var2 = tk.Radiobutton(tab, text="No", variable=self.cctv_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_cctv_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "15. Are security guards present to patrol the premises?\n")
        option_security_guards_var1 = tk.Radiobutton(tab, text="Yes", variable=self.security_guards_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_security_guards_var1)
        text_widget.insert(tk.END, "\n")
        option_security_guards_var2 = tk.Radiobutton(tab, text="No", variable=self.security_guards_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_security_guards_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "16. Is biometric access control implemented for sensitive areas?\n")
        option_biometric_var1 = tk.Radiobutton(tab, text="Yes", variable=self.biometric_access_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_biometric_var1)
        text_widget.insert(tk.END, "\n")
        option_biometric_var2 = tk.Radiobutton(tab, text="No", variable=self.biometric_access_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_biometric_var2)
        text_widget.insert(tk.END, "\n")

        # Employee Education and Awareness
        text_widget.insert(tk.END, "\nEMPLOYEE EDUCATION AND AWARENESS\n", "custom_tag")
        text_widget.insert(tk.END, "17. Do employees receive regular security awareness training?\n")
        option_security_awareness_var1 = tk.Radiobutton(tab, text="Yes", variable=self.security_awareness_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_security_awareness_var1)
        text_widget.insert(tk.END, "\n")
        option_security_awareness_var2 = tk.Radiobutton(tab, text="No", variable=self.security_awareness_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_security_awareness_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "18. Are employees educated on password best practices?\n")
        option_password_best_practices_var1 = tk.Radiobutton(tab, text="Yes", variable=self.password_best_practices_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_password_best_practices_var1)
        text_widget.insert(tk.END, "\n")
        option_password_best_practices_var2 = tk.Radiobutton(tab, text="No", variable=self.password_best_practices_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_password_best_practices_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "19. Are employees trained to identify and report phishing attempts?\n")
        option_phishing_training_var1 = tk.Radiobutton(tab, text="Yes", variable=self.phishing_training_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_phishing_training_var1)
        text_widget.insert(tk.END, "\n")
        option_phishing_training_var2 = tk.Radiobutton(tab, text="No", variable=self.phishing_training_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_phishing_training_var2)
        text_widget.insert(tk.END, "\n")

        text_widget.insert(tk.END, "20. Are employees trained on proper data handling and protection?\n")
        option_data_handling_var1 = tk.Radiobutton(tab, text="Yes", variable=self.data_handling_var, value="yes",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_handling_var1)
        text_widget.insert(tk.END, "\n")
        option_data_handling_var2 = tk.Radiobutton(tab, text="No", variable=self.data_handling_var, value="no",font=radio_font)
        text_widget.window_create(tk.END, window=option_data_handling_var2)
        text_widget.insert(tk.END, "\n")

        button_assess = tk.Button(tab, text="Assess", command=self.perform_security_assessment,bg='#0052cc',fg='#ffffff',width=10,height=2,font=('Arial',16))
        text_widget.configure(font=('Arial', 12),state="disabled")
        text_widget.window_create(tk.END, window=button_assess)
        text_widget.insert(tk.END, "\n")

    # Add other tabs and their content methods here
    # Menu Bar
    def create_menu(self):
        menubar = tk.Menu(self.window)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save", command=self.save_file)
        file_menu.add_command(label="Exit", command=self.window.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about_dialog)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.window.config(menu=menubar)

    def save_file(self):
        text_content = self.text_widget.get("1.0", tk.END)

        file_path = tk.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(text_content)
                messagebox.showinfo("Save", "File saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while saving the file: {str(e)}")
        else:
            messagebox.showwarning("Save", "File not saved.")
    def perform_security_assessment(self):
        # Perform the security assessment based on the selected options
        secure_score = 0

        # Network Security
        firewall = self.firewall_var.get()
        print(firewall)
        if firewall == "yes":
            print("this")
            secure_score += 20

        segmentation = self.segmentation_var.get()
        if segmentation == "yes":
            secure_score += 20

        ids_ips = self.ids_ips_var.get()
        if ids_ips == "yes":
            secure_score += 20

        encryption = self.encryption_var.get()
        if encryption == "yes":
            secure_score += 20
        # System Security
        patching = self.patching_var.get()
        if patching == "yes":
            secure_score += 20

        password_policy = self.password_policy_var.get()
        if password_policy == "yes":
            secure_score += 20

        admin_privileges = self.admin_privileges_var.get()
        if admin_privileges == "yes":
            secure_score += 20

        anti_malware = self.anti_malware_var.get()
        if anti_malware == "yes":
            secure_score += 20

        # Data Security
        access_control = self.access_control_var.get()
        if access_control == "yes":
            secure_score += 20

        data_encryption = self.data_encryption_var.get()
        if data_encryption == "yes":
            secure_score += 20

        data_backup = self.data_backup_var.get()
        if data_backup == "yes":
            secure_score += 20

        data_retention = self.data_retention_var.get()
        if data_retention == "yes":
            secure_score += 20

        # Physical Security
        access_control = self.access_control_var.get()
        if access_control == "yes":
            secure_score += 20

        cctv = self.cctv_var.get()
        if cctv == "yes":
            secure_score += 20

        security_guards = self.security_guards_var.get()
        if security_guards == "yes":
            secure_score += 20

        biometric = self.biometric_access_var.get()
        if biometric == "yes":
            secure_score += 20

        # Employee Education and Awareness
        security_training = self.security_awareness_var.get()
        if security_training == "yes":
            secure_score += 20

        password_best_practices = self.password_best_practices_var.get()
        if password_best_practices == "yes":
            secure_score += 20

        phishing_awareness = self.phishing_training_var.get()
        if phishing_awareness == "yes":
            secure_score += 20

        data_handling = self.data_handling_var.get()
        if data_handling == "yes":
            secure_score += 20

        secure_percentage = (secure_score / 100) * 100
        messagebox.showinfo("Security Assessment", f"Secure Percentage: {secure_percentage}%")

    def show_about_dialog(self):
        messagebox.showinfo("About", "Reconnaissance and Vulnerability Assessment Software: is a powerful and comprehensive reconnaissance and vulnerability assessment software designed to assist organizations in identifying and mitigating potential security risks. It combines advanced scanning techniques with intelligent analysis to provide accurate and actionable insights into an organization's security posture.\n\nKey Features: \n   Reconnaissance\n   Vulnerability Assessment" )


def main():
    window = tk.Tk()
    app = SecurityAssessmentGUI(window)
    window.wm_iconbitmap("app_icon.ico")
    window.mainloop()

if __name__ == "__main__":
    main()
