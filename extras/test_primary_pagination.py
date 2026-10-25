import io
import json
import unittest
from unittest.mock import patch
import inventory_sources as s

URL='https://api.github.com/repos/php/php-src/security-advisories'
class Response(io.BytesIO):
    def __init__(self,rows,link='',url=URL):
        super().__init__(json.dumps(rows).encode()); self.headers={'Link':link}; self.url=url
    def geturl(self): return self.url

class PaginationTests(unittest.TestCase):
    def test_all_pages_and_aggregate_evidence(self):
        with patch.object(s.urllib.request,'urlopen',side_effect=[Response([{'ghsa_id':'one'}],f'<{URL}?page=2>; rel="next"'),Response([{'ghsa_id':'two'}])]):
            result=s._fetch_json(URL)
        self.assertEqual(result['pages'],2)
        self.assertEqual([r['ghsa_id'] for r in result['document']],['one','two'])
        self.assertEqual(len(result['sha256']),64)

    def test_foreign_pagination_fails_closed(self):
        with patch.object(s.urllib.request,'urlopen',return_value=Response([], '<https://evil.invalid/>; rel="next"')):
            with self.assertRaisesRegex(ValueError,'untrusted'): s._fetch_json(URL)

    def test_rate_limit_error_is_not_empty_advisories(self):
        with patch.object(s.urllib.request,'urlopen',return_value=Response({'message':'rate limit'})):
            with self.assertRaisesRegex(ValueError,'schema'): s._fetch_json(URL)

    def test_node_index_adapter_and_electron_components(self):
        url='https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json'
        with patch.object(s,'_fetch_json',return_value={'document':{'1':{'vulnerable':'24.x','patched':'^24.1.0'}}}):
            self.assertEqual(s._fetch_source(url,'node-core-json')['document']['node_core'][0]['_record_id'],'1')
        snap={'source_url':'official','retrieved_at':'now','sha256':'digest','document':[{'version':'40.0.0','node':'24.1.0'},{'version':'40.1.0','node':'24.2.0'},{'version':'41.0.0','node':'26.0.0'}]}
        rows=s._release_drift([{'ecosystem':'electron','name':'electron','version':'40.0.0'}],[snap],'official')
        self.assertEqual(rows[0]['installed_release_components'],{'node':'24.1.0'})
        self.assertEqual(rows[0]['same_major_latest'],'40.1.0')
        self.assertEqual(rows[0]['security_fixed'],'unknown')

if __name__=='__main__': unittest.main()
