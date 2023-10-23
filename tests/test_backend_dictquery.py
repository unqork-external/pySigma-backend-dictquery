"""
Unqork Security - Threat Detection and Response - PySigma Dictquery Backend Tests
"""
# import glob
# import os.path
import unittest

from sigma.backends.dictquery import DictQueryBackend
from sigma.collection import SigmaCollection


class DictQueryBackendTest(unittest.TestCase):
    """
    DictQueryBackendTest - Tests for the DictQueryBackend class
    """

    def setup_backend():
        """
        setup_backend - generic setup of test backend
        """
        return DictQueryBackend()

    def simple_test(self, yaml, expected):
        """
        simple_test - common simple test of running a YAML blob through the backend and comparing against expect value
        """
        sigma_rule = SigmaCollection.from_yaml(yaml)
        backend = DictQueryBackendTest.setup_backend()
        actual = backend.convert(sigma_rule)
        self.assertListEqual(actual, expected)

    def test_dictquery_and_expression(self):
        """test for AND expressions"""
        yaml = """
    title: Test
    status: test
    logsource:
        category: test_category
        product: test_product
    detection:
        sel:
            fieldA: valueA
            fieldB: valueB
        condition: sel
    """
        expected = ["fieldA=='valueA' AND fieldB=='valueB'"]
        self.simple_test(yaml, expected)

    def test_dictquery_or_expression(self):
        """test for OR expressions"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel1:
                fieldA: valueA
            sel2:
                fieldB: valueB
            condition: 1 of sel*
        """
        expected = ["fieldA=='valueA' OR fieldB=='valueB'"]
        self.simple_test(yaml, expected)

    def test_dictquery_and_or_expression(self):
        """test for AND OR expressions"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA:
                    - valueA1
                    - valueA2
                fieldB:
                    - valueB1
                    - valueB2
            condition: sel
        """
        expected = [
            "(fieldA IN ['valueA1', 'valueA2']) AND (fieldB IN ['valueB1', 'valueB2'])"
        ]
        self.simple_test(yaml, expected)

    def test_dictquery_or_and_expression(self):
        """test for OR AND expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel1:
                fieldA: valueA1
                fieldB: valueB1
            sel2:
                fieldA: valueA2
                fieldB: valueB2
            condition: 1 of sel*
        """
        expected = [
            "(fieldA=='valueA1' AND fieldB=='valueB1') OR (fieldA=='valueA2' AND fieldB=='valueB2')"
        ]
        self.simple_test(yaml, expected)

    def test_dictquery_in_expression(self):
        """test for IN expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA:
                    - valueA
                    - valueB
                    - valueC*
            condition: sel
        """
        expected = ["fieldA=='valueA' OR fieldA=='valueB' OR fieldA LIKE 'valueC*'"]
        self.simple_test(yaml, expected)

    def test_dictquery_contains(self):
        """test for |contains expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA|contains: foo
            condition: sel
        """
        expected = ["fieldA LIKE '*foo*'"]
        self.simple_test(yaml, expected)

    def test_dictquery_startswith(self):
        """test for |startswith expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA|startswith: foo
            condition: sel
        """
        expected = ["fieldA LIKE 'foo*'"]
        self.simple_test(yaml, expected)

    def test_dictquery_endswith(self):
        """test for |endswith expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA|endswith: foo
            condition: sel
        """
        expected = ["fieldA LIKE '*foo'"]
        self.simple_test(yaml, expected)

    def test_dictquery_regex_query(self):
        """test for regular expression expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA|re: foo.*bar
                fieldB: foo
            condition: sel
        """
        expected = ["fieldA MATCH /foo.*bar/ AND fieldB=='foo'"]
        self.simple_test(yaml, expected)

    def test_dictquery_cidr_query(self):
        """test for |cidr expression"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field|cidr: 192.168.0.0/16
            condition: sel
        """
        expected = ["field LIKE '192.168.*'"]
        self.simple_test(yaml, expected)

    def test_dictquery_field_name_with_whitespace(self):
        """test for field name with whitespace"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field name: value
            condition: sel
        """
        expected = ["`field name`=='value'"]
        self.simple_test(yaml, expected)

    def test_dictquery_field_name_with_dot(self):
        """test for fieldname with dot"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                Field.nAme: value
            condition: sel
        """
        expected = ["`Field.nAme`=='value'"]
        self.simple_test(yaml, expected)

    def test_dictquery_field_name_with_underscore(self):
        """test for fieldname with underscore"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                field_name: value
            condition: sel
        """
        expected = ["`field_name`=='value'"]
        self.simple_test(yaml, expected)

    def test_dictquery_field_name_with_dash(self):
        """test for fieldname with dash"""
        yaml = """
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                FIELD.ONE-TWO: value
            condition: sel
        """
        expected = ["`FIELD.ONE-TWO`=='value'"]
        self.simple_test(yaml, expected)

    # def test_dictquery_realworld(self):
    #     """test against real world files"""
    #     backend = DictQueryBackendTest.setup_backend()
    #     folder = os.path.join(os.path.expanduser("~"), "dev/tdr-rules/sigma/prod")
    #     files = glob.glob("*.sigma", root_dir=folder, recursive=True)
    #     files.sort()
    #     for file in files:
    #         with self.subTest(file):
    #             fullpath = os.path.join(folder, file)
    #             with open(fullpath, "r") as f_in:
    #                 sigma_str = f_in.read()
    #             print(f"==== FILE {file}")
    #             if "sumo_query" in sigma_str:
    #                 print("   SUMO QUERY")
    #             else:
    #                 try:
    #                     sigma_rule = SigmaCollection.from_yaml(
    #                         sigma_str, collect_errors=True
    #                     )
    #                 except Exception as e:
    #                     self.fail(f"Exception during reading {file} {e}")
    #                 else:
    #                     should_convert = True
    #                     for rule in sigma_rule.rules:
    #                         print(f"   ERRORS: {rule.errors}")
    #                         for cond in rule.detection.condition:
    #                             if "|" in cond:
    #                                 should_convert = False
    #                                 print("   PIPE RULE")
    #                                 break
    #                     if should_convert:
    #                         try:
    #                             dictquery_str = backend.convert(sigma_rule)
    #                             print(f"   CONVERSION: '{dictquery_str}'")
    #                         except Exception as e:
    #                             self.fail(f"Exception during conversion {file} {e}")
