import unittest
import pandas as pd
from backend.parser import parse_ipdr_csv, build_connection_graph
from backend.anomaly import detect_anomalies

class TestIPDRParser(unittest.TestCase):
    def setUp(self):
        self.df = parse_ipdr_csv('data/sample_ipdr.csv')

    def test_parse_columns(self):
        self.assertIn('a_party', self.df.columns)
        self.assertIn('b_party', self.df.columns)
        self.assertEqual(len(self.df), 10)

    def test_graph_construction(self):
        G = build_connection_graph(self.df)
        self.assertGreaterEqual(G.number_of_edges(), 10)

    def test_anomaly_detection(self):
        anomalies = detect_anomalies(self.df)
        self.assertTrue(any(a['type'] == 'too_many_connections' for a in anomalies))
        self.assertTrue(any(a['type'] == 'blacklisted_ip' for a in anomalies))
        self.assertTrue(any(a['type'] == 'bidirectional_loop' for a in anomalies))

if __name__ == '__main__':
    unittest.main()
