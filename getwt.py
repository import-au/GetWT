from flask import Flask, render_template, request
import sqlite3 as sql
import data_gather
import logging
import sys
import time
import configparser
import socket

app = Flask(__name__)
logging.basicConfig()

config = configparser.ConfigParser()

try:
    with open('etc/config.cfg') as f:
        config.read_file(f)
    _detected_urls = config.get('VIRUSTOTAL', 'MALWARE')
except IOError:
    logging.error("Config file not found")
    sys.exit(1)

@app.route('/')
def new():
    return render_template('job.html')


@app.route('/results', methods=['POST', 'GET'])
def results():
    if request.method == 'POST':
        try:
            form_job_id = request.form['job_id']
            if form_job_id is None or form_job_id == "":
                job_id = str(int(time.time()))
                logging.info(job_id)
            else:
                job_id = form_job_id
                logging.info(job_id)

            form_ips = request.form['ip']
            if '\r\n' in form_ips:
                ips = form_ips.split('\r\n')
                logging.info(ips)
            else:
                ips = (form_ips,)
                logging.info(ips)

            for ip in ips:
                vt_data = data_gather.get_vt_passive_dns(ip)
                pt_data = data_gather.get_pt_passive_dns(ip)

                if vt_data[0]:
                    data_gather.store_passive_dns("vt", vt_data[1], ip, job_id, malware=_detected_urls)
                if pt_data[0]:
                    data_gather.store_passive_dns("pt", pt_data[1], ip, job_id)

                data_gather.store_web_tech(job_id)

            con = sql.connect("etc/passive_dns.db")
            con.row_factory = sql.Row

            cur = con.cursor()
            cur.execute("""SELECT passivedns.value, passivedns.type, webtechnologies.url, 
                            webtechnologies.app, webtechnologies.version, webtechnologies.type as web_type 
                        FROM 
                            passivedns 
                        INNER JOIN 
                            webtechnologies 
                        WHERE
                            passivedns.jobid = ?
                        GROUP BY 
                            webtechnologies.url, webtechnologies.app, webtechnologies.version""", (job_id,))
            results = cur.fetchall()
            msg = "Successfully ran"
        except:
            msg = sys.exc_info()[0]
            results = dict(error=sys.exc_info()[0])
        finally:
            return render_template("result.html", msg=msg, results=results)
            con.close()
    elif request.method == 'GET':
        form_job_id = request.args.get('job_id')
        con = sql.connect("etc/passive_dns.db")
        con.row_factory = sql.Row

        cur = con.cursor()

        if form_job_id is None or form_job_id == "":
            cur.execute("""SELECT passivedns.value, passivedns.type, webtechnologies.url, 
                            webtechnologies.app, webtechnologies.version, webtechnologies.type as web_type 
                        FROM 
                            passivedns 
                        INNER JOIN 
                            webtechnologies 
                        GROUP BY 
                            webtechnologies.url, webtechnologies.app, webtechnologies.version""")
        else:
            cur.execute("""SELECT passivedns.value, passivedns.type, webtechnologies.url, 
                            webtechnologies.app, webtechnologies.version, webtechnologies.type as web_type 
                        FROM 
                            passivedns 
                        INNER JOIN 
                            webtechnologies 
                        WHERE
                            passivedns.jobid = ?
                        GROUP BY 
                            webtechnologies.url, webtechnologies.app, webtechnologies.version""", (form_job_id,))
        results = cur.fetchall()
        return render_template("result.html", results=results)
        con.close()


if __name__ == '__main__':
    port = config.getint('MODE', 'PORT')
    host = config.get('MODE', 'HOST')
    try:
        app.run(host=host, port=port, debug=True)
    except socket.gaierror:
        logging.error("No Valid Host Configuration")
        sys.exit(1)
