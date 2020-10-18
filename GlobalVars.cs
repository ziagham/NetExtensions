using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Extensions
{
    public static class GlobalVars
    {
        /// <summary>
        /// An enumeration of the types of masking styles for the Mask() extension method
        /// of the string class.
        /// </summary>
        public enum MaskStyle
        {
            /// <summary>
            /// Masks all characters within the masking region, regardless of type.
            /// </summary>
            All,

            /// <summary>
            /// Masks only alphabetic and numeric characters within the masking region.
            /// </summary>
            AlphaNumericOnly,
        }
    }
}
