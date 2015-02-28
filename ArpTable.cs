//
// ArpTable.cs
//
// Author:
//   Aaron Bockover <abock@xamarin.com>
//
// Copyright 2015 Xamarin Inc. All rights reserved.

using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// Analysis disable InconsistentNaming

using in_addr = System.UInt32;
using socklen_t = System.UInt32;

namespace Mono.Posix
{
	public class ArpTable : IEnumerable<ArpTable.Entry>
	{
		readonly List<Entry> entries = new List<Entry> ();

		public event Action<Entry> EntryResolved;

		public struct Entry
		{
			public IPAddress IPAddress { get; set; }
			public PhysicalAddress PhysicalAddress { get; set; }
		}

		public void Resolve ()
		{
			int [] mib = {
				Sysctl.CLT_NET,
				Socket.PF_ROUTE,
				0,
				Socket.AF_INET,
				Socket.NET_RT_FLAGS,
				Route.RTF_LLINFO
			};

			var sysctlBufSize = IntPtr.Zero;
			if (Sysctl.sysctl (mib, (uint)mib.Length,
				IntPtr.Zero, ref sysctlBufSize, IntPtr.Zero, IntPtr.Zero) < 0)
				throw new Exception ("sysctl: unable to estimate routing table size");

			var buf = Marshal.AllocHGlobal (sysctlBufSize);

			try {
				if (Sysctl.sysctl (mib, (uint)mib.Length,
					buf, ref sysctlBufSize, IntPtr.Zero, IntPtr.Zero) < 0)
					throw new Exception ("sysctl: unable to retrieve routing table");

				var rtmSize = Marshal.SizeOf<Route.rt_msghdr> ();
				var sainarpSize = Marshal.SizeOf<Ethernet.sockaddr_inarp> ();

				Route.rt_msghdr rtm;
				var lim = (long)buf + (long)sysctlBufSize;

				for (var next = (long)buf; next < lim; next += rtm.rtm_msglen) {
					rtm = Marshal.PtrToStructure<Route.rt_msghdr> ((IntPtr)next);
					var sin = Marshal.PtrToStructure<Ethernet.sockaddr_inarp> ((IntPtr)(next + rtmSize));
					var sdl = Marshal.PtrToStructure<NetLinkLevel.sockaddr_dl> ((IntPtr)(next + rtmSize + sainarpSize));

					var entry = new Entry {
						IPAddress = new IPAddress (sin.sin_addr)
					};

					if (sdl.sdl_alen > 0) {
						var phaddr = new byte [sdl.sdl_alen];
						Array.Copy (sdl.sdl_data, 0, phaddr, 0, sdl.sdl_alen);
						entry.PhysicalAddress = new PhysicalAddress (phaddr);
					}

					entries.Add (entry);

					OnEntryResolved (entry);
				}
			} finally {
				Marshal.FreeHGlobal (buf);
			}
		}

		protected virtual void OnEntryResolved (Entry entry)
		{
			var handler = EntryResolved;
			if (handler != null)
				handler (entry);
		}

		public IEnumerator<Entry> GetEnumerator ()
		{
			foreach (var entry in entries)
				yield return entry;
		}

		IEnumerator IEnumerable.GetEnumerator ()
		{
			return GetEnumerator ();
		}
	}

	#region Native Interop

	/// <summary>members from net/route.h</summary>
	static class Route
	{
		public const int RTF_LLINFO = 0x400;
		public const int RTA_NETMASK = 0x4;

		[StructLayout (LayoutKind.Sequential)]
		public struct rt_metrics
		{
			public uint rmx_locks;
			public uint rmx_mtu;
			public uint rmx_hopcount;
			public int rmx_expire;
			public uint rmx_recvpipe;
			public uint rmx_sendpipe;
			public uint rmx_ssthresh;
			public uint rmx_rtt;
			public uint rmx_rttvar;
			public uint rmx_pksent;
			public uint rmx_filler_0;
			public uint rmx_filler_1;
			public uint rmx_filler_2;
			public uint rmx_filler_3;
		}

		[StructLayout (LayoutKind.Sequential)]
		public struct rt_msghdr
		{
			public ushort rtm_msglen;
			public byte rtm_version;
			public byte rtm_type;
			public ushort rtm_index;
			public int rtm_flags;
			public int rtm_addrs;
			public int rtm_pid;
			public int rtm_seq;
			public int rtm_errno;
			public int rtm_use;
			public uint rtm_inits;
			public rt_metrics rtm_rmx;
		}
	}

	/// <summary>members from netinet/if_ether.h<summary>
	static class Ethernet
	{
		public const int SIN_PROXY = 0x1;
		public const int SIN_ROUTER = 0x2;

		[StructLayout (LayoutKind.Sequential)]
		public struct sockaddr_inarp
		{
			public byte sin_len;
			public byte sin_family;
			public ushort sin_port;
			public in_addr sin_addr;
			public in_addr sin_srcaddr;
			public ushort sin_tos;
			public ushort sin_other;
		};
	}

	/// <summary>members from net/if_dl.h</summary>
	static class NetLinkLevel
	{
		[StructLayout (LayoutKind.Sequential)]
		public struct sockaddr_dl
		{
			public byte sdl_len;
			public byte sdl_family;
			public ushort sdl_index;
			public byte sdl_type;
			public byte sdl_nlen;
			public byte sdl_alen;
			public byte sdl_slen;
			[MarshalAs (UnmanagedType.ByValArray, SizeConst = 12)]
			public byte [] sdl_data;
		}
	}

	/// <summary>members from socket.h</summary>
	static class Socket
	{
		public const int AF_ROUTE = 17;
		public const int PF_ROUTE = AF_ROUTE;
		public const int AF_INET = 2;
		public const int NET_RT_FLAGS = 2;
	}

	/// <summary>members from sysctl.h</summary>
	static class Sysctl
	{
		public const int CLT_NET = 4;

		[DllImport ("libc")]
		public static extern int sysctl (
			int [] name, uint namelen,
			IntPtr oldp, ref IntPtr oldlenp,
			IntPtr newp, IntPtr newlen);
	}

	#endregion
}