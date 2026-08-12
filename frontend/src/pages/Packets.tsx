import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { importPcap, listPackets } from "../api/endpoints";
import type { Packet } from "../api/types";
import { InlineError, Spinner } from "../components/Spinner";
import { useToast } from "../components/toast";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

const PROTOCOLS = ["tcp", "udp", "icmp", "other"];
const PAGE_SIZE = 25;

const inputClass =
  "rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 focus:border-emerald-500 focus:outline-hidden";

const PROTO_STYLES: Record<string, string> = {
  tcp: "bg-sky-500/20 text-sky-300 ring-sky-500/40",
  udp: "bg-violet-500/20 text-violet-300 ring-violet-500/40",
  icmp: "bg-amber-500/20 text-amber-300 ring-amber-500/40",
  other: "bg-slate-500/20 text-slate-300 ring-slate-500/40",
};

export default function Packets() {
  useDocumentTitle("Packets");
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const { success } = useToast();

  const canManage = user?.role !== "viewer";

  const [srcIp, setSrcIp] = useState("");
  const [dstIp, setDstIp] = useState("");
  const [proto, setProto] = useState("");
  const [page, setPage] = useState(1);
  const [file, setFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ ingested: number; alerts: number } | null>(null);

  const packetsQuery = useQuery({
    queryKey: ["packets", "list", { srcIp, dstIp, proto, page }],
    queryFn: () =>
      listPackets({
        src_ip: srcIp || undefined,
        dst_ip: dstIp || undefined,
        proto: proto || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  });

  const upload = useMutation({
    mutationFn: (input: File) => importPcap(input),
    onSuccess: (result) => {
      setLastResult(result);
      setUploadError(null);
      setFile(null);
      success(`Imported ${result.ingested} packet(s), ${result.alerts} alert(s).`);
      void queryClient.invalidateQueries({ queryKey: ["packets"] });
      if (result.alerts > 0) {
        void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      }
    },
    onError: (err: Error) => setUploadError(err.message),
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setUploadError(null);
    setLastResult(null);
    if (!file) {
      setUploadError("Choose a .pcap file to upload.");
      return;
    }
    upload.mutate(file);
  }

  function applyFilters(event: FormEvent) {
    event.preventDefault();
    setPage(1);
    void packetsQuery.refetch();
  }

  const packets = packetsQuery.data?.items ?? [];
  const total = packetsQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Packets</h1>
        <p className="text-sm text-slate-400">
          {total} captured packet{total === 1 ? "" : "s"}
        </p>
      </header>

      {canManage && (
        <form
          onSubmit={handleSubmit}
          className="space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4"
        >
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">
              Pcap capture upload
            </label>
            <input
              type="file"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream"
              onChange={(event) => {
                setFile(event.target.files?.[0] ?? null);
                setLastResult(null);
                setUploadError(null);
              }}
              className={`${inputClass} w-full file:mr-3 file:cursor-pointer file:rounded-md file:border-0 file:bg-emerald-500 file:px-3 file:py-1 file:text-xs file:font-semibold file:text-slate-950 hover:file:bg-emerald-400`}
            />
            <p className="mt-1 text-xs text-slate-500">
              Upload a raw pcap capture. IP packets are parsed and run through the detection engine.
            </p>
          </div>
          {lastResult && (
            <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
              Imported {lastResult.ingested} packet(s) and generated {lastResult.alerts} alert(s).
            </p>
          )}
          <InlineError message={uploadError ?? ""} />
          <button
            type="submit"
            disabled={upload.isPending}
            className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
          >
            {upload.isPending ? "Uploading…" : "Upload & analyze"}
          </button>
        </form>
      )}

      {packetsQuery.isError && (
        <InlineError message={packetsQuery.error?.message ?? "Failed to load packets"} />
      )}

      <section className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Destination</th>
              <th className="px-4 py-3">Proto</th>
              <th className="px-4 py-3">Size</th>
              <th className="px-4 py-3">File</th>
            </tr>
            <tr className="border-b border-slate-800">
              <th colSpan={6} className="px-4 py-2">
                <form onSubmit={applyFilters} className="flex flex-wrap items-center gap-2">
                  <input
                    className={inputClass}
                    value={srcIp}
                    onChange={(event) => setSrcIp(event.target.value)}
                    placeholder="Source IP"
                    aria-label="Source IP filter"
                  />
                  <input
                    className={inputClass}
                    value={dstIp}
                    onChange={(event) => setDstIp(event.target.value)}
                    placeholder="Dest IP"
                    aria-label="Destination IP filter"
                  />
                  <select
                    className={inputClass}
                    value={proto}
                    onChange={(event) => setProto(event.target.value)}
                    aria-label="Protocol filter"
                  >
                    <option value="">Any protocol</option>
                    {PROTOCOLS.map((item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                  <button
                    type="submit"
                    className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Apply
                  </button>
                  <button
                    type="button"
                    onClick={() => void packetsQuery.refetch()}
                    className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Refresh
                  </button>
                </form>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {packetsQuery.isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center">
                  <Spinner />
                </td>
              </tr>
            )}
            {!packetsQuery.isLoading && packets.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No packets match the current filters.
                </td>
              </tr>
            )}
            {packets.map((packet, index) => (
              <PacketRow key={`${packet.id ?? "raw"}-${index}`} packet={packet} />
            ))}
          </tbody>
        </table>
      </section>

      <div className="flex items-center justify-between text-sm text-slate-400">
        <p>
          Page {page} of {totalPages} · {total} total
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((value) => Math.max(1, value - 1))}
            className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-40"
          >
            Previous
          </button>
          <button
            type="button"
            disabled={page >= totalPages}
            onClick={() => setPage((value) => value + 1)}
            className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

function PacketRow({ packet }: { packet: Packet }) {
  return (
    <tr className="hover:bg-slate-800/50">
      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
        {new Date(packet.ts).toLocaleString()}
      </td>
      <td className="px-4 py-3">
        <span className="font-mono text-slate-200">{packet.src_ip}</span>
        {packet.src_port !== null && <span className="text-slate-500">:{packet.src_port}</span>}
      </td>
      <td className="px-4 py-3">
        <span className="font-mono text-slate-200">{packet.dst_ip}</span>
        {packet.dst_port !== null && <span className="text-slate-500">:{packet.dst_port}</span>}
      </td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ${
            PROTO_STYLES[packet.proto] ?? PROTO_STYLES.other
          }`}
        >
          {packet.proto}
        </span>
      </td>
      <td className="px-4 py-3 text-slate-400">{packet.length} B</td>
      <td className="px-4 py-3 text-xs text-slate-500">{packet.raw_ref ?? "—"}</td>
    </tr>
  );
}
