/**
 * A response tool to help in determining whether a machine has been infected with Crypto Ransomware.
 * 
 * Author: Brett Hawkins
 * Date Created: 5/23/2015
 * 
 * */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Management.Instrumentation;
using System.ServiceProcess;
using System.Net.NetworkInformation;
using System.Net;
using System.DirectoryServices;
using System.Collections;
using System.Security.AccessControl;


namespace crsponse
{
    class crsponse
    {
        // arguments that can be passed
        private static string regArg = "-reg";
        private static string procArg = "-proc";
        private static string filesArg = "-files";
        private static string allArg = "-all";
        private static string userArg = "-user";
        private static string helpArg = "--help";

        // global variables used
        private static String machineName;
        private static String directoryName;
        private static String osName;
        private static String userSID;
        private static String userName;
        private static List<String> summary = new List<String>(); //list to hold summary
        private static List<FileInfo> allFiles = new List<FileInfo>();  // list that will hold the files
        private static List<String> normalFilesCWindows = new List<String>(); // list to hold normal files that run in C:\Windows


        static void Main(string[] args)
        {
            // if there are no arguments display a help message
            if (args.Length == 0)
            {
                Console.Write("\ncrsponse v1.0 - Crypto Ransomware Response Tool\nCopyright (C) 2015 Brett Hawkins\nTwitter Handle: @hawkbluedevil\n\n");
                Console.Write("Description:\n\t A response tool to help in determining whether a machine\n\t has been infected with Crypto Ransomware.\n\n");
                Console.Write("Usage:\n\t crsponse -user <user> -all  \t Check for files, processes & reg keys");
                Console.Write("\n\t crsponse -user <user> -reg \t Check for known effected reg keys");
                Console.Write("\n\t crsponse -user <user> -proc \t Check for known effected processes");
                Console.Write("\n\t crsponse -user <user> -files \t Check for known effected files\n\n");
                Console.Write("Examples:\n\t crsponse -user bond -all\n\t crsponse -user batman -reg\n\t crsponse -user superman -proc\n\t crsponse -user spiderman -files\n");


            }


            // if user needs help, display a help message
            else if (args[0].ToLower().Equals(helpArg) && args.Length == 1)
            {
                Console.Write("\ncrsponse v1.0 - Crypto Ransomware Response Tool\nCopyright (C) 2015 Brett Hawkins\nTwitter Handle: @hawkbluedevil\n\n");
                Console.Write("Description:\n\t A response tool to help in determining whether a machine\n\t has been infected with Crypto Ransomware.\n\n");
                Console.Write("Usage:\n\t crsponse -user <user> -all  \t Check for files, processes & reg keys");
                Console.Write("\n\t crsponse -user <user> -reg \t Check for known effected reg keys");
                Console.Write("\n\t crsponse -user <user> -proc \t Check for known effected processes");
                Console.Write("\n\t crsponse -user <user> -files \t Check for known effected files\n\n");
                Console.Write("Examples:\n\t crsponse -user bond -all\n\t crsponse -user batman -reg\n\t crsponse -user superman -proc\n\t crsponse -user spiderman -files\n");

            } // end if user needs help

            // is user has entered arguments, not being the help argument
            else if (args.Length > 1)
            {
                // if a user has been supplied as an argument correctly
                if (args[0].ToLower().Equals(userArg) && !args[1].Equals("") && args[1] != null)
                {

                    // if a correct argument has been given to check for crypto ransomware behavior
                    if (args.Length == 3 && (args[2].ToLower().Equals(regArg) || args[2].ToLower().Equals(allArg) || args[2].ToLower().Equals(procArg) || args[2].ToLower().Equals(filesArg)))
                    {
                        initializeVars(args[1].ToLower());

                        // if the user exists on the machine
                        if (userSID != null)
                        {
                            // if user wants all
                            if (args[2].ToLower().Equals(allArg))
                            {

                                searchKnownCryptoFiles(machineName);
                                getProcesses(machineName);
                                getRegistryKeys(machineName);

                            }

                            // if user wants just reg keys
                            else if (args[2].ToLower().Equals(regArg))
                            {
                                getRegistryKeys(machineName);


                            }

                            // if user wants just processes
                            else if (args[2].ToLower().Equals(procArg))
                            {

                                getProcesses(machineName);

                            }

                            // if user wants just files
                            else if (args[2].ToLower().Equals(filesArg))
                            {
                                searchKnownCryptoFiles(machineName);
                            }

                            // write summary to file
                            if (summary.Count > 0)
                            {
                                Console.WriteLine("Analyzing Summary...");
                                StreamWriter fileOfSummary = new StreamWriter("./" + directoryName + "/" + machineName + "_SUMMARY.csv");
                                fileOfSummary.WriteLine("***FILE SUMMARY***");
                                foreach (String item in summary)
                                {
                                    fileOfSummary.WriteLine(item.ToString());
                                }

                                fileOfSummary.Close();
                                Console.WriteLine("Analyzing Summary Complete...\r\n");
                                Console.WriteLine("Please go to below directory to view SUMMARY file.");
                                Console.WriteLine(Environment.CurrentDirectory + "\\" + directoryName);

                            } // end writing to the summary file

                        } // end if the user exists on the machine

                        else
                        {
                            Console.WriteLine("\r\nUser SID not found for user entered. Try another user.");
                        }

                    } // end if a correct argument has been given to check for crypto ransomware behavior

                    // if the correct argument has not been given to check for crypto ransomware behavior
                    else
                    {
                        Console.Write("\nType crsponse --help for help.\n");
                    }

                } // end if a user has been supplied as an argument correctly

            } // end if user has entered arguments, not being the help argument


             // if user types any incorrect switches, display a help message
            else
            {

                Console.Write("\nType crsponse --help for help.\n");

            } // end if user types any incorrect switches, display help message

        } // end main


        /**
        * Initialize needed variables
        * 
        * */
        public static void initializeVars(String username)
        {
            machineName = Environment.MachineName;
            osName = getOSName();
            userName = username;
            userSID = user2SID(userName.ToUpper());
            directoryName = machineName + "_info";
            if (userSID != null && !userSID.Equals(""))
            {
                DirectoryInfo di = Directory.CreateDirectory(directoryName);
                Console.WriteLine("============================================================");
                Console.WriteLine("Machine Name: " + machineName);
                Console.WriteLine("Operating System: " + osName);
                Console.WriteLine("User Name: " + userName);
                Console.WriteLine("User SID: " + userSID);
                Console.WriteLine("Directory of Output Files: " + directoryName);
                Console.WriteLine("============================================================\r\n");
                normalFilesCWindows.Add("bfsvc.exe");
                normalFilesCWindows.Add("explorer.exe");
                normalFilesCWindows.Add("helppane.exe");
                normalFilesCWindows.Add("hh.exe");
                normalFilesCWindows.Add("notepad.exe");
                normalFilesCWindows.Add("regedit.exe");
                normalFilesCWindows.Add("splwow64.exe");
                normalFilesCWindows.Add("twunk_16.exe");
                normalFilesCWindows.Add("twunk_32.exe");
                normalFilesCWindows.Add("winhelp.exe");
                normalFilesCWindows.Add("winhlp32.exe");
                normalFilesCWindows.Add("write.exe");
            }



        }

        /**
         * Convert username to SID
         * 
         * */
        public static string user2SID(String username)
        {
            String sidConverted = "";
            try
            {
                var account = new NTAccount(username);
                var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                sidConverted = sid.ToString();

            }

            catch (IdentityNotMappedException ex)
            {

                sidConverted = null;

            }
            return sidConverted;

        } // end convert username to SID


        /**
        * Return the name of the OS based on revision number
        * 
        * win7 = 6.1   win8 = 6.2  win8.1 = 6.3   win10 = 10.0
        * win xp = 5.1  win xp pro = 5.2  win vista = 6.0  
        **/
        public static String getOSName()
        {

            String os = Environment.OSVersion.VersionString;

            if (os.Contains("5.1"))
            {
                return "Windows XP";
            }
            else if (os.Contains("5.2"))
            {
                return "Windows XP Pro";
            }

            else if (os.Contains("6.0"))
            {
                return "Windows Vista";
            }

            else if (os.Contains("6.1"))
            {
                return "Windows 7";
            }

            else if (os.Contains("6.2"))
            {
                return "Windows 8";
            }

            else if (os.Contains("6.3"))
            {
                return "Windows 8.1";
            }

            else if (os.Contains("10.0"))
            {
                return "Windows 10";
            }

            else
            {
                return "Operating System Unknown";
            }


        } // end get os name


        /**
        * Get all processes on system and write to CSV file
        * 
        * 
        * */
        public static void getProcesses(String machineName)
        {
            summary.Add("\r\n\r\n***PROCESS SUMMARY***");

            Console.WriteLine("Getting Processes...");

            // create processes csv file in directory that was created for machine
            StreamWriter file = new StreamWriter("./" + directoryName + "/" + machineName + "_processes.csv");
            try
            {
                Process[] processList = Process.GetProcesses(machineName);
                file.WriteLine("PROCESS,FULL PATH,PID,SID,MEMORY USAGE");

                // grab each of the running processes from the processList
                foreach (Process process in processList)
                {
                    var bytestoKb = Math.Round((double)process.WorkingSet64 / 1024, 0); // convert bytes to KB
                    String fullpath = GetMainModuleFilepath(process.Id); // get full path of running process
                    file.WriteLine(process.ProcessName + "," + fullpath + "," + process.Id + "," + process.SessionId + "," + bytestoKb + " KB");

                    // if the process name and full path are not null, analyse the process
                    if (process.ProcessName != null && fullpath != null)
                    {
                        analyzeProcesses(process.ProcessName.ToLower(), fullpath.ToLower());
                    }



                } // end grabbing each of running processes from the processList
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());

            }

            file.Close();
            Console.WriteLine("Getting Processes Complete...");

        } // end get processes method

        /**
        * Get relevant registry keys on system and write to CSV file
        * 
        * 
        * */
        public static void getRegistryKeys(String machineName)
        {
            summary.Add("\r\n\r\n***REGISTRY SUMMARY***");
            Console.WriteLine("Getting Registry Keys...");

            // create reg key csv file in directory that was created for machine
            StreamWriter file = new StreamWriter("./" + directoryName + "/" + machineName + "_registry_keys.csv");

            // current user run keys
            Microsoft.Win32.RegistryKey HKCURunOnce = Microsoft.Win32.Registry.Users.OpenSubKey(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            Microsoft.Win32.RegistryKey HKCURun = Microsoft.Win32.Registry.Users.OpenSubKey(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            Microsoft.Win32.RegistryKey HKCURunOnceEx = Microsoft.Win32.Registry.Users.OpenSubKey(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx");

            // desktop key to loook for wallpaper
            Microsoft.Win32.RegistryKey HKCUControlPanel = Microsoft.Win32.Registry.Users.OpenSubKey(userSID + "\\Control Panel\\Desktop");

            // hku and hku/software reg keys
            Microsoft.Win32.RegistryKey HKCUSoftware = Microsoft.Win32.Registry.Users.OpenSubKey(userSID + "\\Software");
            Microsoft.Win32.RegistryKey HKCU = Microsoft.Win32.Registry.Users.OpenSubKey(userSID);

            // local machine run keys
            Microsoft.Win32.RegistryKey HKLMRunOnce = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            Microsoft.Win32.RegistryKey HKLMRun = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            Microsoft.Win32.RegistryKey HKLMRunOnceEx = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx");

            // run start services
            Microsoft.Win32.RegistryKey HKLMRunServicesonce = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce");
            Microsoft.Win32.RegistryKey HKLMRunServices = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices");

            // boot execute
            Microsoft.Win32.RegistryKey HKLMBootExecute = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet\\Control\\Session Manager\\BootExecute");

            //user initialize when logging on
            Microsoft.Win32.RegistryKey HKLMUserInit = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit");

            //start shell
            Microsoft.Win32.RegistryKey HKLMShell = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell");

            // local machine run keys for 32 bit apps running on 64 bit OS
            Microsoft.Win32.RegistryKey HKLM32BitRunOnce = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
            Microsoft.Win32.RegistryKey HKLM32BitRun = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
            Microsoft.Win32.RegistryKey HKLM32BitRunOnceEx = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx");

            try
            {
                // for each reg key that exists, grab the key and all values or subkeys for some of those keys, and write them to the CSV file
                if (HKCURunOnce != null)
                {
                    file.WriteLine(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                    foreach (string appName in HKCURunOnce.GetValueNames())
                    {
                        file.WriteLine((string)HKCURunOnce.GetValue(appName));
                        analyzeRegKeys(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", (string)HKCURunOnce.GetValue(appName));

                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKCURun != null)
                {
                    file.WriteLine(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                    foreach (string appName in HKCURun.GetValueNames())
                    {
                        file.WriteLine((string)HKCURun.GetValue(appName));
                        analyzeRegKeys(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", (string)HKCURun.GetValue(appName));

                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKCURunOnceEx != null)
                {
                    file.WriteLine(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx");
                    foreach (string appName in HKCURunOnceEx.GetValueNames())
                    {
                        file.WriteLine((string)HKCURunOnceEx.GetValue(appName));
                        analyzeRegKeys(userSID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", (string)HKCURunOnceEx.GetValue(appName));

                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMRunOnce != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                    foreach (string appName in HKLMRunOnce.GetValueNames())
                    {
                        file.WriteLine((string)HKLMRunOnce.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", (string)HKLMRunOnce.GetValue(appName));

                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMRun != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                    foreach (string appName in HKLMRun.GetValueNames())
                    {
                        file.WriteLine((string)HKLMRun.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", (string)HKLMRun.GetValue(appName));

                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMRunOnceEx != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx");
                    foreach (string appName in HKLMRunOnceEx.GetValueNames())
                    {
                        file.WriteLine((string)HKLMRunOnceEx.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", (string)HKLMRunOnceEx.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMRunServicesonce != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce");
                    foreach (string appName in HKLMRunServicesonce.GetValueNames())
                    {
                        file.WriteLine((string)HKLMRunServicesonce.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", (string)HKLMRunServicesonce.GetValue(appName));
                    }
                }


                file.WriteLine("\r\n\r\n");


                if (HKLMRunServices != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices");
                    foreach (string appName in HKLMRunServices.GetValueNames())
                    {
                        file.WriteLine((string)HKLMRunServices.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", (string)HKLMRunServices.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMBootExecute != null)
                {
                    file.WriteLine("HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute");
                    foreach (string appName in HKLMBootExecute.GetValueNames())
                    {
                        file.WriteLine((string)HKLMBootExecute.GetValue(appName));
                        analyzeRegKeys("HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute", (string)HKLMBootExecute.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMUserInit != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit");
                    foreach (string appName in HKLMUserInit.GetValueNames())
                    {
                        file.WriteLine((string)HKLMUserInit.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit", (string)HKLMUserInit.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLMShell != null)
                {
                    file.WriteLine("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell");
                    foreach (string appName in HKLMShell.GetValueNames())
                    {
                        file.WriteLine((string)HKLMShell.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", (string)HKLMShell.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLM32BitRunOnce != null)
                {
                    file.WriteLine("HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                    foreach (string appName in HKLM32BitRunOnce.GetValueNames())
                    {
                        file.WriteLine((string)HKLM32BitRunOnce.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", (string)HKLM32BitRunOnce.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLM32BitRun != null)
                {
                    file.WriteLine("HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
                    foreach (string appName in HKLM32BitRun.GetValueNames())
                    {
                        file.WriteLine((string)HKLM32BitRun.GetValue(appName));
                        analyzeRegKeys("HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", (string)HKLM32BitRun.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKLM32BitRunOnceEx != null)
                {
                    file.WriteLine("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx");
                    foreach (string appName in HKLM32BitRunOnceEx.GetValueNames())
                    {
                        file.WriteLine((string)HKLM32BitRunOnceEx.GetValue(appName));
                        analyzeRegKeys("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", (string)HKLM32BitRunOnceEx.GetValue(appName));
                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKCUControlPanel != null)
                {
                    file.WriteLine(userSID + "\\Control Panel\\Desktop|Wallpaper");
                    foreach (string appName in HKCUControlPanel.GetValueNames())
                    {
                        if (appName.ToLower().Equals("wallpaper"))
                        {
                            file.WriteLine(appName + "," + HKCUControlPanel.GetValue(appName).ToString());
                            analyzeRegKeys(userSID + "\\Control Panel\\Desktop|Wallpaper", HKCUControlPanel.GetValue(appName).ToString());
                        }

                    }
                }

                file.WriteLine("\r\n\r\n");


                if (HKCUSoftware != null)
                {
                    file.WriteLine(userSID + "\\Software");
                    string[] names = HKCUSoftware.GetSubKeyNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        file.WriteLine(names[i].ToString());
                        analyzeRegKeys(userSID + "\\Software", names[i].ToString());


                    }

                }

                file.WriteLine("\r\n\r\n");


                if (HKCU != null)
                {
                    file.WriteLine(userSID);
                    string[] names = HKCU.GetSubKeyNames();
                    for (int i = 0; i < names.Length; i++)
                    {
                        file.WriteLine(names[i].ToString());
                        analyzeRegKeys(userSID, names[i].ToString());

                    }

                }

                file.WriteLine("\r\n\r\n");

            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

            file.Close();
            Console.WriteLine("Getting Registry Keys Complete...");
        } // end getRegistryKeys


        /**
        * Analyze for known directories for crypto ransomware processes to be running and add them to summary list
        * 
        * */
        public static void analyzeProcesses(String processName, String fullPath)
        {
            String userPath = "";
            String appDataPath = "";

            // determine appropriate user dir and appdata dir based on OS
            if (osName.Equals("Windows XP") || osName.Equals("Windows XP Pro"))
            {
                userPath = "documents and settings";
                appDataPath = "application data";
            }
            else
            {
                userPath = "users";
                appDataPath = "appdata";
            }

            // %AppData%
            if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %AppDataLocal%
            else if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\local"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %AppDataRoaming%
            else if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\roaming"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %ProgramData%
            else if (fullPath.Contains("c:\\programdata"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %UserProfile%
            else if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower()))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %Temp%
            else if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\local\\temp"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %C:\\%
            else if (fullPath.Contains("c:\\" + processName))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %WinDir%
            else if (fullPath.Contains("c:\\windows\\" + processName) && !normalFilesCWindows.Contains(processName.ToLower() + ".exe"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %AppDataLocal%\Microsoft\Windows
            else if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\local\\microsoft\\windows"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }
            // %AppData%\Microsoft\Windows
            else if (fullPath.Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\microsoft\\windows"))
            {
                String finding = "\r\nProcess Name," + processName + "\r\nFull Path," + fullPath;
                if (!summary.Contains(finding))
                {
                    summary.Add(finding);
                }
            }

        } // end analyzeProcesses

        /**
         * Add reg keys used by crypto ransomware to summary list as long as they are not null
         * 
        * */
        public static void analyzeRegKeys(String regKey, String appName)
        {
            if (regKey != null && appName != null & !appName.Equals(""))
            {

                summary.Add("\r\nRegistry Key," + regKey + "\r\nRegistry Value," + appName);
            }
        } // end analyzeRegKeys


        /**
        * Get full file path for given process
        * 
        * */
        public static string GetMainModuleFilepath(int processId)
        {
            string wmiQueryString = "SELECT ProcessId, ExecutablePath FROM Win32_Process WHERE ProcessId = " + processId;
            using (var searcher = new ManagementObjectSearcher(wmiQueryString))
            {
                using (var results = searcher.Get())
                {
                    ManagementObject mo = results.Cast<ManagementObject>().FirstOrDefault();
                    if (mo != null)
                    {
                        return (string)mo["ExecutablePath"];
                    }
                }
            }
            return null;

        } // end get full file path for process


        /**
       * Search for known crypto files, and write to file
       * 
       * 
       * */
        public static void searchKnownCryptoFiles(String machineName)
        {

            String userPath = "";
            String appDataPath = "";

            // determine appropriate user dir and appdata dir based on OS
            if (osName.Equals("Windows XP") || osName.Equals("Windows XP Pro"))
            {
                userPath = "Documents and Settings";
                appDataPath = "Application Data";
            }
            else
            {
                userPath = "Users";
                appDataPath = "AppData";
            }
            Console.WriteLine("Getting Files...");

            StreamWriter files = new StreamWriter("./" + directoryName + "/" + machineName + "_files.csv");

            // get all files relevent directories
            DirectoryInfo AppData = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\" + appDataPath);
            DirectoryInfo AppDataLocal = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\" + appDataPath + "\\Local");
            DirectoryInfo AppDataLocalMicroWindows = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\" + appDataPath + "\\Local\\Microsoft\\Windows");
            DirectoryInfo AppDataRoaming = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\" + appDataPath + "\\Roaming");
            DirectoryInfo Temp = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\" + appDataPath + "\\Local\\Temp");
            DirectoryInfo programData = new DirectoryInfo("C:\\ProgramData");
            DirectoryInfo userProfile = new DirectoryInfo("C:\\" + userPath + "\\" + userName);
            DirectoryInfo winDir = new DirectoryInfo("C:\\Windows");
            DirectoryInfo cDrive = new DirectoryInfo("C:\\");
            DirectoryInfo appDataRoamingMicroWindows = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\" + appDataPath + "\\Roaming\\Microsoft\\Windows");
            DirectoryInfo desktop = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Desktop");
            DirectoryInfo documents = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Documents");
            DirectoryInfo pictures = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Pictures");
            DirectoryInfo videos = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Music");
            DirectoryInfo music = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Documents");
            DirectoryInfo allUsers = new DirectoryInfo("C:\\" + userPath + "\\" + "All Users");
            DirectoryInfo tasks = new DirectoryInfo("C:\\Windows\\Tasks");
            DirectoryInfo dropbox = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Dropbox");
            DirectoryInfo googleDrive = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Google Drive");
            DirectoryInfo oneDrive = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\OneDrive");
            DirectoryInfo startup = new DirectoryInfo("C:\\" + userPath + "\\" + userName + "\\Start Menu\\Programs\\Startup");


            // get files in directories and subdirs 1 level deep
            if (allUsers.Exists)
            {
                foreach (DirectoryInfo dir in allUsers.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }
            if (tasks.Exists)
            {
                foreach (DirectoryInfo dir in tasks.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }
            if (startup.Exists)
            {
                foreach (DirectoryInfo dir in startup.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }
            if (AppData.Exists)
            {
                foreach (DirectoryInfo dir in AppData.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (AppDataLocal.Exists)
            {

                foreach (DirectoryInfo dir in AppDataLocal.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (AppDataLocalMicroWindows.Exists)
            {
                foreach (DirectoryInfo dir in AppDataLocalMicroWindows.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (AppDataRoaming.Exists)
            {
                foreach (DirectoryInfo dir in AppDataRoaming.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (Temp.Exists)
            {
             
                foreach (DirectoryInfo dir in Temp.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (programData.Exists)
            {
                foreach (DirectoryInfo dir in programData.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (userProfile.Exists)
            {
                foreach (DirectoryInfo dir in userProfile.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (winDir.Exists)
            {
                foreach (DirectoryInfo dir in winDir.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (cDrive.Exists)
            {
                foreach (DirectoryInfo dir in cDrive.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (appDataRoamingMicroWindows.Exists)
            {
                foreach (DirectoryInfo dir in appDataRoamingMicroWindows.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (desktop.Exists)
            {
                foreach (DirectoryInfo dir in desktop.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (documents.Exists)
            {
                foreach (DirectoryInfo dir in documents.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (dropbox.Exists)
            {
                foreach (DirectoryInfo dir in dropbox.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (googleDrive.Exists)
            {
                foreach (DirectoryInfo dir in googleDrive.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (oneDrive.Exists)
            {
                foreach (DirectoryInfo dir in oneDrive.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (pictures.Exists)
            {
                foreach (DirectoryInfo dir in pictures.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (videos.Exists)
            {
                foreach (DirectoryInfo dir in videos.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }

            if (music.Exists)
            {
                foreach (DirectoryInfo dir in music.GetDirectories("*", SearchOption.TopDirectoryOnly))
                {
                    FullDirList(dir, "*", allFiles);
                }
            }


            // create CSV file with file names and attributes of relevant directories
            files.WriteLine("FILE NAME,ATTRIBUTES,CREATION TIME,LAST UPDATED,LAST ACCESS,DIRECTORY NAME");
            foreach (FileInfo finfo in allFiles)
            {
                files.WriteLine(finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName);
            }


            files.Close();
            Console.WriteLine("Getting Files Complete...");
            analyzeFiles(); // analyze files listed

        } // end searchKnownCryptoFiles method


        /**
        * Gets full directory listing
        * 
        * 
        * */
        public static void FullDirList(DirectoryInfo dir, string searchPattern, List<FileInfo> fileList)
        {

            // list the files
            try
            {
                foreach (FileInfo f in dir.GetFiles(searchPattern))
                {
                    if (!fileList.Contains(f))
                    {
                        fileList.Add(f);
                    }
                }
            }
            catch (Exception ex)
            {
                return;
            }

        } // end full directory listing method


        /**
        * Analyze files for known crypto ransomware files
        * 
        * 
        * */
        public static void analyzeFiles()
        {

            summary.Add("\r\nFILE NAME,ATTRIBUTES,CREATION TIME,LAST UPDATED,LAST ACCESS,DIRECTORY NAME");

            String userPath = "";
            String appDataPath = "";

            // determine correect user and appdata path based on OS
            if (osName.Equals("Windows XP") || osName.Equals("Windows XP Pro"))
            {
                userPath = "documents and settings";
                appDataPath = "application data";
            }
            else
            {
                userPath = "users";
                appDataPath = "appdata";
            }

            // analyze each file collected
            foreach (FileInfo finfo in allFiles)
            {

                // splash screen page
                if (finfo.Name.ToLower().Contains("decrypt_instructions"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains("help_decrypt"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains("help_to_decrypt_your_files"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains("help_restore_files"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains("help_to_save_files"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains("allfilesarelocked"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains("decryptallfiles"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains(".html") && finfo.DirectoryName.ToLower().Contains("c:\\users\\" + userName.ToLower() + "\\documents"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // splash screen page
                else if (finfo.Name.ToLower().Contains(".html") && finfo.DirectoryName.ToLower().Equals("c:\\users\\all users"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // list of encrypted files by bitcryptor
                else if (finfo.Name.ToLower().Contains("bitcryptorfilelist"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // wallpaper indicating files are encrypted
                else if (finfo.Name.ToLower().Contains("wallpaper.jpg"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // list of files encrypted
                else if (finfo.Name.ToLower().Contains("filelist"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // list of files encrypted
                else if (finfo.Name.ToLower().Contains("sfile"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // list of files encrypted
                else if (finfo.Name.ToLower().Contains("coinvaultfilelist.txt"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // files in known effected directories
                else if (finfo.DirectoryName.ToLower().Equals("c:\\" + userPath + "\\" + userName + "\\" + appDataPath + "\\roaming\\microsoft\\windows"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // exe related to coinvault
                else if (finfo.Name.ToLower().Contains("coinvault.exe"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }
                // coinvault file
                else if (finfo.Name.ToLower().Contains("edone") && finfo.DirectoryName.ToLower().Equals("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\roaming\\microsoft\\windows"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // file in known effected directory that are not a "normal" windows file
                else if (finfo.DirectoryName.ToLower().Contains("c:\\windows") && !finfo.DirectoryName.ToLower().Contains("system32") && !finfo.DirectoryName.ToLower().Contains("syswow64") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\ehome") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\camera") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\filemanager") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\ccm") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\ccmsetup") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\winstore") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\immersivecontrolpanel") && !finfo.DirectoryName.ToLower().Equals("c:\\windows\\servicing") && !finfo.DirectoryName.ToLower().Contains("prefetch") && finfo.Name.ToLower().Contains(".exe") && !finfo.Name.ToLower().Contains(".exe.") && !normalFilesCWindows.Contains(finfo.Name.ToLower()))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // random 7 character job not including ".job" in known directory(ex: fsielcs.job)
                else if (finfo.DirectoryName.ToLower().Equals("c:\\windows\\tasks") && finfo.Name.Length == 11)
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }
                // splash screen file in known effected directory
                else if (finfo.DirectoryName.ToLower().Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\local\\temp") && finfo.Name.ToLower().Contains(".jpg"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // encrypted extensions
                else if (finfo.Name.ToLower().Contains(".ecc") || finfo.Name.ToLower().Contains(".exx") || finfo.Name.ToLower().Contains(".ezz") || finfo.Name.ToLower().Contains(".encrypted") || finfo.Name.ToLower().Contains(".ctb") || finfo.Name.ToLower().Contains(".ctb2"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // files in known effected directories, specifically appdata directories
                else if ((finfo.DirectoryName.ToLower().Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\local\\temp") || finfo.DirectoryName.ToLower().Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\local") || finfo.DirectoryName.ToLower().Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath + "\\roaming") || finfo.DirectoryName.ToLower().Contains("c:\\" + userPath + "\\" + userName.ToLower() + "\\" + appDataPath)) && finfo.Name.ToLower().Contains(".exe") && !finfo.Name.ToLower().Contains(".exe."))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }

                // files in startup programs directory
                else if (finfo.DirectoryName.ToLower().Equals("c:\\" + userPath + "\\" + userName.ToLower() + "\\start menu\\programs\\startup"))
                {
                    String finding = finfo.Name.Replace(",", " ") + "," + finfo.Attributes.ToString().Replace(",", " | ") + "," + finfo.CreationTime + "," + finfo.LastWriteTime + "," + finfo.LastAccessTime + "," + finfo.DirectoryName;
                    if (!summary.Contains(finding))
                    {
                        summary.Add(finding);
                    }
                }


            } // end foreach file that was collected

        } // end analyzeFiles method

    } // and crsponse class

} // and crsponse namespace
