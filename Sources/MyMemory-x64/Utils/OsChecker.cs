using System;
using System.Management;

namespace MyMemory_x64.Utils
{
    public static class OsChecker
    {

        public enum EWindowsVersion
        {
            Unknown,
            Windows7_SP0,
            Windows7_SP1,
            Windows8_0,
            Windows8_1,
            Windows10_0
        }

        public static EWindowsVersion GetWindowsVersion()
        {

            string version = null;
            int? servicePack = null;

            ManagementClass osClass = new ManagementClass("Win32_OperatingSystem");
            foreach (ManagementObject queryObj in osClass.GetInstances())
            {
                foreach (PropertyData prop in queryObj.Properties)
                {

                    if (prop.Name == "Version" && prop.Type == CimType.String)
                    {
                        version = (string)prop.Value;
                    }

                    if (prop.Name == "ServicePackMajorVersion" && prop.Type == CimType.UInt16)
                    {
                        servicePack = (ushort)prop.Value;
                    }
                }
            }

            if (version == null || !servicePack.HasValue)
            {
                return EWindowsVersion.Unknown;
            }

            if (version.StartsWith("10.0"))
            {
                return EWindowsVersion.Windows10_0;
            }
            if (version.StartsWith("6.3"))
            {
                return EWindowsVersion.Windows8_1;
            }
            if (version.StartsWith("6.2"))
            {
                return EWindowsVersion.Windows8_0;
            }
            if (version.StartsWith("6.1"))
            {
                if (servicePack == 1)
                {
                    return EWindowsVersion.Windows7_SP1;
                }
                else
                {
                    return EWindowsVersion.Windows7_SP0;
                }
            }

            return EWindowsVersion.Unknown;

        }

    }
}
