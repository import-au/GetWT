import sys
import configparser
import ipaddress
import logging
import json
import sqlite3
import ast
from clues import Clues
from detection import Detector
from output import JSONOutput
from urllib.parse import unquote, urlparse

logging.basicConfig(level=logging.DEBUG)

try:
    import requests
except ImportError:
    logging.error("Install requests")
    sys.exit(1)

config = configparser.ConfigParser()
try:
    with open('etc/config.cfg') as f:
        config.read_file(f)
except IOError:
    logging.error("Config file not found")
    sys.exit(1)

_passive_total_url = config.get('PASSIVETOTAL', 'URL')
_passive_total_key = config.get('PASSIVETOTAL', 'KEY')
_passive_total_user = config.get('PASSIVETOTAL', 'USERNAME')
_virus_total_url = config.get('VIRUSTOTAL', 'URL')
_virus_total_key = config.get('VIRUSTOTAL', 'KEY')

check_virus_total = True
check_passive_total = True

if _passive_total_key is None:
    check_passive_total = False

if _virus_total_key is None:
    check_virus_total = False

def get_pt_passive_dns(ip):

    if check_passive_total:
        session = requests.Session()

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            error = ip + " does not appear to be a valid IP address"
            logging.error(error)
            return False, error

        headers = {"Content-Type": "application/json"}
        data = {"query": ip}
        auth = (_passive_total_user, _passive_total_key)

        try:
            response = session.get(url=_passive_total_url, auth=auth, headers=headers, json=data)
        except ConnectionError:
            error = "Connection to PassiveTotal API failed for " + ip
            logging.error(error)
            return False, error
        except requests.HTTPError:
            error = "PassiveTotal returned an Invalid HTTP response"
            logging.error(error)
            return False, error
        except requests.Timeout:
            error = "Connection to PassiveTotal timed out"
            logging.error(error)
            return False, error
        except requests.TooManyRedirects:
            error = "Request to PassiveTotal has exceeded too many redirects"
            logging.error(error)
            return False, error

        if response.status_code == 200:
            try:
                passive_total_data = response.json()
                return True, passive_total_data
            except ValueError:
                error = "Unable to parse PassiveTotal response as json"
                logging.error(error)
                return False, error
        elif response.status_code == 401:
            error = "Authorization Failed to PassiveTotal"
            logging.error(error)
            return False, error
        elif response.status_code == 400:
            error = "PassiveTotal is unable to determine the query type"
            logging.error(error)
            return False, error
        elif response.status_code == 402:
            error = "API quota exceeded for PassiveTotal"
            logging.error(error)
            return False, error
        else:
            error = "Unhandled status code for PassiveTotal"
            logging.error(error)
            return False, error
    else:
        error = "No Passive Total Key Provided"
        logging.error(error)
        return False, error


def store_passive_dns(data_source, data, query, jobid, malware=None):
    if malware is None:
        malware = False

    try:
        json.dumps(data)
    except ValueError:
        error = "Data passed is not valid JSON"
        logging.error(error)
        return False, error
    else:
        conn = sqlite3.connect('etc/passive_dns.db')
        c = conn.cursor()
        if data_source == "pt":
            if "results" in data:
                for record in data['results']:
                    c.execute("""INSERT OR REPLACE INTO passivedns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                              (jobid, data_source, record['firstSeen'], record['collected'], record['lastSeen'],
                               record['recordType'], record['resolveType'], ', '.join(record['source']),
                               record['value'], record['recordHash'], record['resolve']))
        elif data_source == "vt":
            if "resolutions" in data:
                for record in data['resolutions']:
                    c.execute("""INSERT OR REPLACE INTO passivedns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                              (jobid, data_source, None, None, record['last_resolved'], None, None, None, query, None,
                               unquote(record['hostname'])))
            if malware:
                if "detected_urls" in data:
                    for record in data['detected_urls']:
                        c.execute("""INSERT OR REPLACE INTO passivedns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                  (jobid, data_source, record['scan_date'], None, None, None, None, None, query, None,
                                   record['url']))
        conn.commit()
        conn.close()


def get_vt_passive_dns(ip):
    if check_virus_total:
        session = requests.Session()

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            error = ip + " does not appear to be a valid IP address"
            logging.error(error)
            return False, error

        headers = {"Content-Type": "application/json"}
        data = {"ip": ip, "apikey": _virus_total_key}

        try:
            response = session.get(url=_virus_total_url, headers=headers, params=data)
        except ConnectionError:
            error = "Connection to VirusTotal API failed for " + ip
            logging.error(error)
            return False, error
        except requests.HTTPError:
            error = "VirusTotal returned an Invalid HTTP response"
            logging.error(error)
            return False, error
        except requests.Timeout:
            error = "Connection to VirusTotal timed out"
            logging.error(error)
            return False, error
        except requests.TooManyRedirects:
            error = "Request to VirusTotal has exceeded too many redirects"
            logging.error(error)
            return False, error

        if response.status_code == 200:
            try:
                passive_total_data = response.json()
                return True, passive_total_data
            except ValueError:
                error = "Unable to parse VirusTotal response as json"
                logging.error(error)
                return False, error
        elif response.status_code == 403:
            error = "Authorization Failed to VirusTotal"
            logging.error(error)
            return False, error
        elif response.status_code == 400:
            error = "VirusTotal is unable to determine the query type"
            logging.error(error)
            return False, error
        elif response.status_code == 204:
            error = "API quota exceeded for VirusTotal"
            logging.error(error)
            return False, error
        else:
            error = "Unhandled status code for VirusTotal"
            logging.error(response.status_code)
            logging.error(error)
            return False, error
    else:
        error = "No VirusTotal Key Provided"
        logging.error(error)
        return False, error


def store_web_tech(job):
    conn = sqlite3.connect('etc/passive_dns.db')
    c = conn.cursor()
    c.row_factory = lambda cursor, row: row[0]
    c.execute("""SELECT resolve FROM passivedns WHERE jobid = ?""", (job,))

    urls = c.fetchall()
    sanitized_urls = []
    for url in urls:
        if not str(url).startswith("https://") and not str(url).startswith("http://"):
            url_types = ["https://" + url, "http://" + url]
            for url_type in url_types:
                try:
                    urlparse(url_type, allow_fragments=False)
                    sanitized_urls.append(url_type)
                except ValueError:
                    pass

        if urlparse(url).scheme:
            try:
                urlparse(url, allow_fragments=False)
                sanitized_urls.append(url)
            except ValueError:
                pass
    Clues.get_clues()
    results = Detector().detect_multiple(sanitized_urls, timeout=10)
    output = json.loads(JSONOutput().retrieve(results=results))
    for site in output:
        for record in output[site]:
            if isinstance(ast.literal_eval(record["type"]), dict):
                try:
                    data_type = ast.literal_eval(record["type"])['name']
                    c.execute("""INSERT INTO webtechnologies VALUES (?, ?, ?, ?, ?)""", (job, site, record["app"],
                                                                                         data_type, record["ver"]))
                except TypeError as e:
                    logging.error(ast.literal_eval(record["type"]))
                    logging.error(e)
                    continue
            elif isinstance(ast.literal_eval(record["type"]), tuple):
                try:
                    data_type = str('/'.join(list(str(value["name"]) for value in ast.literal_eval(record['type']))))
                    c.execute("""INSERT INTO webtechnologies VALUES (?, ?, ?, ?, ?)""", (job, site, record["app"],
                                                                                         data_type, record["ver"]))
                except TypeError as e:
                    logging.error(ast.literal_eval(record["type"]))
                    logging.error(e)
                    continue
            else:
                logging.error(ast.literal_eval(record["type"]))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    search_term = "X.X.X.X"
    job_id = "2"
    passive_total = get_pt_passive_dns(search_term)
    if passive_total[0]:
        store_passive_dns("pt", passive_total[1], search_term, job_id)

    virus_total = get_vt_passive_dns(search_term)
    if virus_total[0]:
        store_passive_dns("vt", virus_total[1], search_term, job_id)

    store_web_tech(job_id)
