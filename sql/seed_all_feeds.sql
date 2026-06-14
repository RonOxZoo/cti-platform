-- ============================================================================
-- seed_all_feeds.sql  —  idempotent seed of 100 CTI RSS/scrape sources.
--
-- Generated from master_feeds_100.csv. Safe to re-run any number of times:
--   * url is made UNIQUE, and every INSERT uses ON CONFLICT (url) DO NOTHING,
--     so existing sources are never overwritten or duplicated.
--   * the ALTER ... ADD COLUMN IF NOT EXISTS guards make the schema additions
--     no-ops once applied.
--
-- Column mapping (CSV -> rss_sources):
--   source_name     -> name
--   feed_url        -> url
--   ingest_method   -> ingest_method   (rss | scrape)
--   category        -> category        (global_ti|apt|israel|iran_nexus|
--                                        phishing|cves|ics|research)
--   trust_score     -> trust_score
--   region/translate_first/native_lang -> notes (jsonb)
--   (active = true for all; error_count = 0)
--
-- Apply in the Supabase SQL Editor (see scripts/README.md).
-- ============================================================================

ALTER TABLE rss_sources ADD COLUMN IF NOT EXISTS notes         jsonb;
ALTER TABLE rss_sources ADD COLUMN IF NOT EXISTS ingest_method text;

-- ON CONFLICT (url) needs a unique constraint/index on url.
CREATE UNIQUE INDEX IF NOT EXISTS rss_sources_url_key ON rss_sources (url);

INSERT INTO rss_sources (name, url, category, trust_score, active, ingest_method, notes, error_count) VALUES
  ('Mandiant', 'https://www.mandiant.com/resources/blog/rss.xml', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CrowdStrike', 'https://www.crowdstrike.com/blog/feed/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Palo Alto Unit 42', 'https://unit42.paloaltonetworks.com/feed/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Cisco Talos', 'https://blog.talosintelligence.com/rss/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('SentinelOne Labs', 'https://www.sentinelone.com/labs/feed/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ESET WeLiveSecurity', 'https://www.welivesecurity.com/en/rss/feed/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Sophos News', 'https://news.sophos.com/en-us/feed/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Trend Micro Research', 'https://feeds.trendmicro.com/TrendMicroResearch', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Microsoft MSRC', 'https://msrc.microsoft.com/blog/feed/', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Google Project Zero', 'https://googleprojectzero.blogspot.com/feeds/posts/default', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Recorded Future', 'https://www.recordedfuture.com/feed', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Secureworks', 'https://www.secureworks.com/rss?feed=research&category=blog', 'global_ti', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Dark Reading', 'https://www.darkreading.com/rss.xml', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('SecurityWeek', 'https://www.securityweek.com/feed/', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Krebs on Security', 'https://krebsonsecurity.com/feed/', 'global_ti', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('The Record', 'https://therecord.media/feed/', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Wired Security', 'https://www.wired.com/feed/category/security/latest/rss', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('SC Magazine', 'https://www.scmagazine.com/feed', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Kaspersky Securelist', 'https://securelist.com/feed/', 'apt', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Group-IB', 'https://www.group-ib.com/blog/rss.xml', 'apt', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Team Cymru', 'https://www.team-cymru.com/blog-feed.xml', 'apt', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ThreatConnect', 'https://threatconnect.com/blog/feed/', 'apt', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Anomali', 'https://www.anomali.com/site/blog-rss', 'apt', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Flashpoint', 'https://flashpoint.io/feed/', 'apt', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Intel 471', 'https://intel471.com/blog/feed/', 'apt', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Symantec Threat Intelligence', 'https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/feed', 'apt', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('F-Secure Labs', 'https://labs.withsecure.com/content/dam/labs/rss/rss.xml', 'apt', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Proofpoint', 'https://www.proofpoint.com/us/rss.xml', 'apt', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Check Point Research', 'https://research.checkpoint.com/feed/', 'israel', 0.9, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CyberArk', 'https://www.cyberark.com/blog/feed/', 'israel', 0.85, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Sygnia', 'https://www.sygnia.co/feed/', 'israel', 0.85, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ClearSky Cyber Security', 'https://www.clearskysec.com/feed/', 'israel', 0.88, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Cybereason', 'https://www.cybereason.com/blog/rss.xml', 'israel', 0.85, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Radware', 'https://blog.radware.com/feed/', 'israel', 0.85, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('INCD', 'https://www.gov.il/he/api/PublicationRss/national_cyber_directorate', 'israel', 0.95, true, 'scrape', '{"region": "Israel", "translate_first": true, "native_lang": "he"}'::jsonb, 0),
  ('Israeli CERT', 'https://www.gov.il/en/departments/israel_national_cyber_directorate', 'israel', 0.95, true, 'scrape', '{"region": "Israel", "translate_first": true, "native_lang": "he"}'::jsonb, 0),
  ('Check Point CPR', 'https://blog.checkpoint.com/feed/', 'israel', 0.88, true, 'rss', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Team8', 'https://team8.vc/feed/', 'israel', 0.8, true, 'scrape', '{"region": "Israel", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ClearSky Iran', 'https://www.clearskysec.com/category/reports/feed/', 'iran_nexus', 0.88, true, 'rss', '{"region": "Iran", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Check Point Iran', 'https://research.checkpoint.com/tag/iran/feed/', 'iran_nexus', 0.9, true, 'rss', '{"region": "Iran", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Microsoft MSTIC Iran', 'https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/', 'iran_nexus', 0.9, true, 'rss', '{"region": "Iran", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Recorded Future Iran', 'https://www.recordedfuture.com/research/feed', 'iran_nexus', 0.9, true, 'rss', '{"region": "Iran", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CISA Iran Advisories', 'https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/iran', 'iran_nexus', 0.95, true, 'scrape', '{"region": "Iran", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('PhishTank', 'http://data.phishtank.com/data/online-valid.xml', 'phishing', 0.75, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('APWG', 'https://apwg.org/feed/', 'phishing', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Spamhaus', 'https://www.spamhaus.org/news/feed/', 'phishing', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Malwarebytes Labs', 'https://www.malwarebytes.com/blog/feed/index.xml', 'phishing', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('OpenPhish', 'https://openphish.com/feed.txt', 'phishing', 0.75, true, 'scrape', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('URLhaus', 'https://urlhaus.abuse.ch/feeds/csv_recent/', 'phishing', 0.8, true, 'scrape', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('AbuseIPDB', 'https://www.abuseipdb.com/blog/feed', 'phishing', 0.75, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ANY.RUN', 'https://any.run/cybersecurity-blog/feed/', 'phishing', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CISA KEV', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'cves', 0.95, true, 'scrape', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Exploit-DB', 'https://www.exploit-db.com/rss.xml', 'cves', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Packet Storm', 'https://rss.packetstormsecurity.com/files/', 'cves', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Rapid7', 'https://www.rapid7.com/blog/rss/', 'cves', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Tenable', 'https://www.tenable.com/security/feeds/tra.rss', 'cves', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Qualys', 'https://blog.qualys.com/feed', 'cves', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Snyk', 'https://snyk.io/blog/feed/', 'cves', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('VulnDB', 'https://vulndb.cyberriskanalytics.com/rss', 'cves', 0.85, true, 'scrape', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('NCC Group Research', 'https://research.nccgroup.com/feed/', 'cves', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Vulners', 'https://vulners.com/rss.xml', 'cves', 0.85, true, 'scrape', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ICS-CERT', 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml', 'ics', 0.95, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Dragos', 'https://www.dragos.com/blog/feed/', 'ics', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Claroty', 'https://claroty.com/feed', 'ics', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Nozomi Networks', 'https://www.nozominetworks.com/blog/rss.xml', 'ics', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Waterfall Security', 'https://waterfall-security.com/feed/', 'ics', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Kaspersky ICS', 'https://ics-cert.kaspersky.com/rss/', 'ics', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Fortinet ICS', 'https://feeds.fortinet.com/fortinet/blog/threat-research', 'ics', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Cybereason ICS', 'https://www.cybereason.com/blog/category/research/rss.xml', 'ics', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Google TAG', 'https://blog.google/threat-analysis-group/rss/', 'research', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Citizen Lab', 'https://citizenlab.ca/feed/', 'research', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Stanford Internet Observatory', 'https://cyber.fsi.stanford.edu/io/rss.xml', 'research', 0.88, true, 'scrape', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Atlantic Council Cyber', 'https://www.atlanticcouncil.org/category/blogs/new-atlanticist/feed/', 'research', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Bellingcat Tech', 'https://www.bellingcat.com/feed/', 'research', 0.85, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Microsoft DART', 'https://www.microsoft.com/en-us/security/blog/topic/incident-response/feed/', 'research', 0.9, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Virus Bulletin', 'https://www.virusbulletin.com/rss', 'research', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('SANS ISC', 'https://isc.sans.edu/rssfeed_full.xml', 'research', 0.88, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CISA', 'https://www.cisa.gov/cybersecurity-advisories/all.xml', 'global_ti', 0.95, true, 'rss', '{"region": "USA", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('US-CERT', 'https://www.cisa.gov/uscert/ncas/current-activity.xml', 'global_ti', 0.95, true, 'rss', '{"region": "USA", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('FBI Cyber', 'https://www.ic3.gov/Home/Rss', 'global_ti', 0.95, true, 'scrape', '{"region": "USA", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('NCSC UK', 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', 'global_ti', 0.95, true, 'rss', '{"region": "UK", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ENISA', 'https://www.enisa.europa.eu/media/news-items/news-wire/RSS', 'global_ti', 0.95, true, 'rss', '{"region": "EU", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Australian ACSC', 'https://www.cyber.gov.au/rss/news', 'global_ti', 0.95, true, 'scrape', '{"region": "Australia", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CERT-EU', 'https://cert.europa.eu/publications/threat-intelligence-rss', 'global_ti', 0.95, true, 'rss', '{"region": "EU", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CERT-IL', 'https://www.gov.il/en/api/PublicationRss/cyber_alerts', 'israel', 0.95, true, 'scrape', '{"region": "Israel", "translate_first": true, "native_lang": "he"}'::jsonb, 0),
  ('Kaspersky APT', 'https://securelist.ru/feed/', 'apt', 0.65, true, 'rss', '{"region": "Russia", "translate_first": true, "native_lang": "ru"}'::jsonb, 0),
  ('Group-IB Russia', 'https://www.group-ib.ru/blog/rss/', 'apt', 0.65, true, 'scrape', '{"region": "Russia", "translate_first": true, "native_lang": "ru"}'::jsonb, 0),
  ('Positive Technologies', 'https://www.ptsecurity.com/ru-ru/rss/', 'global_ti', 0.65, true, 'scrape', '{"region": "Russia", "translate_first": true, "native_lang": "ru"}'::jsonb, 0),
  ('BI.ZONE', 'https://bi.zone/rss/', 'global_ti', 0.65, true, 'scrape', '{"region": "Russia", "translate_first": true, "native_lang": "ru"}'::jsonb, 0),
  ('Qihoo 360', 'https://blog.netlab.360.com/rss/', 'global_ti', 0.65, true, 'rss', '{"region": "China", "translate_first": true, "native_lang": "zh"}'::jsonb, 0),
  ('Antiy Labs', 'https://www.antiy.com/rss.xml', 'global_ti', 0.65, true, 'scrape', '{"region": "China", "translate_first": true, "native_lang": "zh"}'::jsonb, 0),
  ('NSFocus', 'https://nsfocusglobal.com/feed/', 'global_ti', 0.65, true, 'rss', '{"region": "China", "translate_first": true, "native_lang": "zh"}'::jsonb, 0),
  ('Sangfor', 'https://www.sangfor.com/blog/rss', 'global_ti', 0.65, true, 'scrape', '{"region": "China", "translate_first": true, "native_lang": "zh"}'::jsonb, 0),
  ('CyberScoop', 'https://www.cyberscoop.com/feed/', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Infosecurity Magazine', 'https://www.infosecurity-magazine.com/rss/news/', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('ZDNet Security', 'https://www.zdnet.com/topic/security/rss.xml', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('CSO Online', 'https://www.csoonline.com/feed/', 'global_ti', 0.8, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0),
  ('Graham Cluley', 'https://grahamcluley.com/feed/', 'global_ti', 0.75, true, 'rss', '{"region": "Global", "translate_first": false, "native_lang": "en"}'::jsonb, 0)
ON CONFLICT (url) DO NOTHING;
