import sqlite3

conn = sqlite3.connect('../etc/passive_dns.db')
c = conn.cursor()

# Create table
c.execute('''CREATE TABLE passivedns
             (jobid int, type text, firstseen text, collected text, lastseen text, recordtype text, resolvetype text,
             source text, value text, recordhash text, resolve text unique)''')

c.execute('''CREATE TABLE webtechnologies
             (jobid int, url text, app text, type text, version text)''')


# Save (commit) the changes
conn.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
conn.close()