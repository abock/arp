using System;

using Mono.Posix;

static class Program
{
	static void Main ()
	{
		var arpTable = new ArpTable ();
		arpTable.EntryResolved += entry =>
			Console.WriteLine ("{0} => {1}", entry.IPAddress, entry.PhysicalAddress);
		arpTable.Resolve ();
	}
}