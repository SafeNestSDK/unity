/*
 * MiniJSON - A minimal JSON parser and serializer for Unity
 * Based on https://gist.github.com/darktable/1411710
 * MIT License
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Tuteliq
{
    internal static class MiniJson
    {
        public static object Deserialize(string json)
        {
            if (json == null) return null;
            return Parser.Parse(json);
        }

        public static string Serialize(object obj)
        {
            return Serializer.Serialize(obj);
        }

        private sealed class Parser : IDisposable
        {
            private const string WORD_BREAK = "{}[],:\"";
            private StringReader json;

            private Parser(string jsonString)
            {
                json = new StringReader(jsonString);
            }

            public static object Parse(string jsonString)
            {
                using var instance = new Parser(jsonString);
                return instance.ParseValue();
            }

            public void Dispose()
            {
                json.Dispose();
                json = null;
            }

            private Dictionary<string, object> ParseObject()
            {
                var table = new Dictionary<string, object>();

                json.Read(); // {

                while (true)
                {
                    switch (NextToken)
                    {
                        case TOKEN.NONE:
                            return null;
                        case TOKEN.CURLY_CLOSE:
                            return table;
                        case TOKEN.COMMA:
                            continue;
                        default:
                            var name = ParseString();
                            if (name == null) return null;

                            if (NextToken != TOKEN.COLON) return null;

                            json.Read(); // :

                            table[name] = ParseValue();
                            break;
                    }
                }
            }

            private List<object> ParseArray()
            {
                var array = new List<object>();

                json.Read(); // [

                var parsing = true;
                while (parsing)
                {
                    var nextToken = NextToken;

                    switch (nextToken)
                    {
                        case TOKEN.NONE:
                            return null;
                        case TOKEN.SQUARED_CLOSE:
                            parsing = false;
                            break;
                        case TOKEN.COMMA:
                            continue;
                        default:
                            var value = ParseByToken(nextToken);
                            array.Add(value);
                            break;
                    }
                }

                return array;
            }

            private object ParseValue()
            {
                var nextToken = NextToken;
                return ParseByToken(nextToken);
            }

            private object ParseByToken(TOKEN token)
            {
                switch (token)
                {
                    case TOKEN.STRING:
                        return ParseString();
                    case TOKEN.NUMBER:
                        return ParseNumber();
                    case TOKEN.CURLY_OPEN:
                        return ParseObject();
                    case TOKEN.SQUARED_OPEN:
                        return ParseArray();
                    case TOKEN.TRUE:
                        return true;
                    case TOKEN.FALSE:
                        return false;
                    case TOKEN.NULL:
                        return null;
                    default:
                        return null;
                }
            }

            private string ParseString()
            {
                var s = new StringBuilder();
                char c;

                json.Read(); // "

                var parsing = true;
                while (parsing)
                {
                    if (json.Peek() == -1)
                    {
                        parsing = false;
                        break;
                    }

                    c = NextChar;
                    switch (c)
                    {
                        case '"':
                            parsing = false;
                            break;
                        case '\\':
                            if (json.Peek() == -1)
                            {
                                parsing = false;
                                break;
                            }

                            c = NextChar;
                            switch (c)
                            {
                                case '"':
                                case '\\':
                                case '/':
                                    s.Append(c);
                                    break;
                                case 'b':
                                    s.Append('\b');
                                    break;
                                case 'f':
                                    s.Append('\f');
                                    break;
                                case 'n':
                                    s.Append('\n');
                                    break;
                                case 'r':
                                    s.Append('\r');
                                    break;
                                case 't':
                                    s.Append('\t');
                                    break;
                                case 'u':
                                    var hex = new char[4];
                                    for (int i = 0; i < 4; i++)
                                        hex[i] = NextChar;
                                    s.Append((char)Convert.ToInt32(new string(hex), 16));
                                    break;
                            }
                            break;
                        default:
                            s.Append(c);
                            break;
                    }
                }

                return s.ToString();
            }

            private object ParseNumber()
            {
                var number = NextWord;

                if (number.IndexOf('.') == -1)
                {
                    if (long.TryParse(number, out long parsedLong))
                        return parsedLong;
                    return 0;
                }

                if (double.TryParse(number, System.Globalization.NumberStyles.Any,
                    System.Globalization.CultureInfo.InvariantCulture, out double parsedDouble))
                    return parsedDouble;
                return 0;
            }

            private void EatWhitespace()
            {
                while (char.IsWhiteSpace(PeekChar))
                {
                    json.Read();
                    if (json.Peek() == -1) break;
                }
            }

            private char PeekChar => Convert.ToChar(json.Peek());

            private char NextChar => Convert.ToChar(json.Read());

            private string NextWord
            {
                get
                {
                    var word = new StringBuilder();

                    while (!IsWordBreak(PeekChar))
                    {
                        word.Append(NextChar);
                        if (json.Peek() == -1) break;
                    }

                    return word.ToString();
                }
            }

            private TOKEN NextToken
            {
                get
                {
                    EatWhitespace();

                    if (json.Peek() == -1) return TOKEN.NONE;

                    switch (PeekChar)
                    {
                        case '{':
                            return TOKEN.CURLY_OPEN;
                        case '}':
                            json.Read();
                            return TOKEN.CURLY_CLOSE;
                        case '[':
                            return TOKEN.SQUARED_OPEN;
                        case ']':
                            json.Read();
                            return TOKEN.SQUARED_CLOSE;
                        case ',':
                            json.Read();
                            return TOKEN.COMMA;
                        case '"':
                            return TOKEN.STRING;
                        case ':':
                            return TOKEN.COLON;
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                        case '8':
                        case '9':
                        case '-':
                            return TOKEN.NUMBER;
                    }

                    switch (NextWord)
                    {
                        case "false":
                            return TOKEN.FALSE;
                        case "true":
                            return TOKEN.TRUE;
                        case "null":
                            return TOKEN.NULL;
                    }

                    return TOKEN.NONE;
                }
            }

            private static bool IsWordBreak(char c)
            {
                return char.IsWhiteSpace(c) || WORD_BREAK.IndexOf(c) != -1;
            }

            private enum TOKEN
            {
                NONE,
                CURLY_OPEN,
                CURLY_CLOSE,
                SQUARED_OPEN,
                SQUARED_CLOSE,
                COLON,
                COMMA,
                STRING,
                NUMBER,
                TRUE,
                FALSE,
                NULL
            }
        }

        private sealed class Serializer
        {
            private StringBuilder builder;

            private Serializer()
            {
                builder = new StringBuilder();
            }

            public static string Serialize(object obj)
            {
                var instance = new Serializer();
                instance.SerializeValue(obj);
                return instance.builder.ToString();
            }

            private void SerializeValue(object value)
            {
                if (value == null)
                {
                    builder.Append("null");
                }
                else if (value is string str)
                {
                    SerializeString(str);
                }
                else if (value is bool b)
                {
                    builder.Append(b ? "true" : "false");
                }
                else if (value is IList list)
                {
                    SerializeArray(list);
                }
                else if (value is IDictionary dict)
                {
                    SerializeObject(dict);
                }
                else if (value is char c)
                {
                    SerializeString(c.ToString());
                }
                else
                {
                    SerializeOther(value);
                }
            }

            private void SerializeObject(IDictionary obj)
            {
                var first = true;
                builder.Append('{');

                foreach (var key in obj.Keys)
                {
                    if (!first) builder.Append(',');
                    SerializeString(key.ToString());
                    builder.Append(':');
                    SerializeValue(obj[key]);
                    first = false;
                }

                builder.Append('}');
            }

            private void SerializeArray(IList array)
            {
                builder.Append('[');

                var first = true;
                foreach (var obj in array)
                {
                    if (!first) builder.Append(',');
                    SerializeValue(obj);
                    first = false;
                }

                builder.Append(']');
            }

            private void SerializeString(string str)
            {
                builder.Append('\"');

                foreach (var c in str)
                {
                    switch (c)
                    {
                        case '"':
                            builder.Append("\\\"");
                            break;
                        case '\\':
                            builder.Append("\\\\");
                            break;
                        case '\b':
                            builder.Append("\\b");
                            break;
                        case '\f':
                            builder.Append("\\f");
                            break;
                        case '\n':
                            builder.Append("\\n");
                            break;
                        case '\r':
                            builder.Append("\\r");
                            break;
                        case '\t':
                            builder.Append("\\t");
                            break;
                        default:
                            if (c < ' ')
                            {
                                builder.Append("\\u");
                                builder.Append(((int)c).ToString("X4"));
                            }
                            else
                            {
                                builder.Append(c);
                            }
                            break;
                    }
                }

                builder.Append('\"');
            }

            private void SerializeOther(object value)
            {
                if (value is float f)
                {
                    builder.Append(f.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
                }
                else if (value is double d)
                {
                    builder.Append(d.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
                }
                else if (value is int or long or byte or sbyte or short or ushort or uint or ulong)
                {
                    builder.Append(value);
                }
                else if (value is decimal dec)
                {
                    builder.Append(dec.ToString(System.Globalization.CultureInfo.InvariantCulture));
                }
                else
                {
                    SerializeString(value.ToString());
                }
            }
        }
    }
}
