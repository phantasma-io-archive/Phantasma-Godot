﻿using System;
using System.Linq;
using System.Text;

namespace LunarLabs.Parser.YAML
{

    public class YAMLWriter
    {
        public static string WriteToString(DataNode node)
        {
            StringBuilder builder = new StringBuilder();
            
            WriteNode(builder, node, 0);

            return builder.ToString();
        }

        private static void WriteNode(StringBuilder buffer, DataNode node, int idents)
        {
            for (int i = 0; i < idents; i++)
            {
                buffer.Append(' ');
            }

            if(node.Name != null && node.Name != ""){
                buffer.Append(node.Name);
                buffer.Append(':');
                buffer.Append(' ');
                if (node.Value != null)
                {
                    buffer.Append(node.Value);
                }
                buffer.AppendLine();
            }

            foreach (var child in node.Children)
            {
                WriteNode(buffer, child, idents + 1);
            }
        }

    }

}
