"""
Unqork Security - Threat Detection and Response - PySigma Dictquery Backend
"""
import re
from typing import ClassVar
from typing import Dict
from typing import Pattern
from typing import Tuple
from typing import Union

from sigma.conditions import ConditionAND
from sigma.conditions import ConditionFieldEqualsValueExpression
from sigma.conditions import ConditionItem
from sigma.conditions import ConditionNOT
from sigma.conditions import ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.types import SigmaCompareExpression
from sigma.types import SigmaRegularExpressionFlag
from sigma.types import SpecialChars


class DictQueryBackend(TextQueryBackend):
    """dictquery backend."""

    name: ClassVar[str] = "dictquery backend"
    formats: Dict[str, str] = {"default": "Plain dictquery queries"}
    requires_pipeline: bool = False

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "=="

    # String output
    # Fields
    # Quoting
    # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote: ClassVar[str] = "`"
    # Quote field names if this pattern matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern: ClassVar[Pattern] = re.compile("^(\\w+[\\.\\s\\-\\_]+\\w*)*$")
    # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    field_quote_pattern_negation: ClassVar[bool] = False

    # Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    # field_escape: ClassVar[str] = ""
    # Escape quote string defined in field_quote
    # field_escape_quote: ClassVar[bool] = True
    # All matches of this pattern are prepended with the string contained in field_escape.
    # field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")

    # Values
    str_quote: ClassVar[
        str
    ] = "'"  # string quoting character (added as escaping character)
    # str_quote_pattern: ClassVar[str] = None
    # str_quote_pattern_negation: ClassVar[str] = None
    escape_char: ClassVar[
        str
    ] = ""  # Escaping character for special characters inside string
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "?"  # Character used as single-character wildcard
    add_escaped: ClassVar[
        str
    ] = ""  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[
        Dict[bool, str]
    ] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} LIKE {value}"
    endswith_expression: ClassVar[str] = "{field} LIKE {value}"
    contains_expression: ClassVar[str] = "{field} LIKE {value}"
    # Special expression if wildcards can't be matched with the eq_token operator
    wildcard_match_expression: ClassVar[str] = "{field} LIKE {value}"

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = "{field} MATCH /{regex}/"
    re_escape_char: ClassVar[
        str
    ] = "\\"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    re_flag_prefix: bool = False  # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "m",
        SigmaRegularExpressionFlag.DOTALL: "s",
    }

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = None
    # CIDR expression query as format string with placeholders {field} = in({list})
    cidr_in_list_expression: ClassVar[str] = "{field} in ({value})"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[str] = "{field} is null"

    # Field existence condition expressions.
    # Expression for field existence as format string with {field} placeholder for field name
    field_exists_expression: ClassVar[str] = "{field}"
    # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    field_not_exists_expression: ClassVar[str] = "NOT {field}"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = False
    # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field} {op} [{list}]"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[str] = "IN"
    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    and_in_operator: ClassVar[str] = None
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = "{value}"
    # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression
    unbound_value_re_expression: ClassVar[str] = " MATCHES /{value}/"

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[
        str
    ] = "\n| "  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[
        str
    ] = "\n| "  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[
        str
    ] = "*"  # String used as query if final query only contains deferred expression

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(
                    SpecialChars.WILDCARD_MULTI
                )  # String ends with wildcard
                and not cond.value[
                    :-1
                ].contains_special()  # Remainder of string doesn't contains special characters
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
                value = cond.value
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = cond.value
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = cond.value
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None
                and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = "{field}" + self.eq_token + "{value}"
                value = cond.value

            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
            )
        except TypeError as te:  # pragma: no cover
            print(te)
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )
