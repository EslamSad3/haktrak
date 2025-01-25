"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { searchLeakX, searchShodan } from "@/lib/api";

interface ShodanResult {
  city?: string;
  country_name?: string;
  ip_str?: string;
  isp?: string;
  last_update?: string;
  ports?: number[];
  vulns?: string[];
  data?: {
    vulns?: {
      [key: string]: {
        verified: boolean;
        cvss: number;
        summary: string;
      };
    };
  }[];
}

interface LeakXResult {
  Services?: {
    host: string;
    port: string;
    protocol: string;
    ip: string;
    cves?: string[];
  }[];
  Leaks?: any[];
  message?: string;
}

export function SearchForm() {
  const [isPending, startTransition] = useTransition();
  const [results, setResults] = useState<{ type: string; data: any } | null>(
    null
  );

  async function handleSubmit(formData: FormData) {
    const query = formData.get("query")?.toString();
    if (!query) return;

    const isDomain =
      /^(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}|localhost)$/i.test(
        query
      );

    startTransition(async () => {
      try {
        let data;
        if (isDomain) {
          data = await searchLeakX(query);
          // Extract CVEs from the LeakX response
          if (data.Services) {
            data.Services = data.Services.map((service) => {
              const cves = service.summary?.match(/CVE-\d{4}-\d{4,7}/g) || [];
              return { ...service, cves };
            });
          }
          setResults({ type: "LeakX", data });
        } else {
          data = await searchShodan(query);
          setResults({ type: "Shodan", data });
        }
        toast.success(`${isDomain ? "LeakX" : "Shodan"} search completed`);
      } catch (error) {
        toast.error(`${isDomain ? "LeakX" : "Shodan"} search failed`);
        setResults(null);
      }
    });
  }

  function renderShodanResults(data: ShodanResult) {
    return (
      <div className="space-y-6 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Property</TableHead>
              <TableHead>Value</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell className="font-medium">City</TableCell>
              <TableCell>{data.city || "N/A"}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-medium">Country</TableCell>
              <TableCell>{data.country_name || "N/A"}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-medium">IP</TableCell>
              <TableCell>{data.ip_str || "N/A"}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-medium">ISP</TableCell>
              <TableCell>{data.isp || "N/A"}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-medium">Last Update</TableCell>
              <TableCell>{data.last_update || "N/A"}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell className="font-medium">Ports</TableCell>
              <TableCell>
                {data.ports ? data.ports.join(", ") : "N/A"}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>

        {data.vulns && data.vulns.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Vulnerabilities</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>CVE</TableHead>
                      <TableHead>CVSS</TableHead>
                      <TableHead>Summary</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.vulns.map((cve) => {
                      const vulnData = data.data?.[0]?.vulns?.[cve];
                      return (
                        <TableRow key={cve}>
                          <TableCell className="font-medium">{cve}</TableCell>
                          <TableCell>{vulnData?.cvss || "N/A"}</TableCell>
                          <TableCell>{vulnData?.summary || "N/A"}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    );
  }

  function renderLeakXResults(data: LeakXResult) {
    if (data.message) {
      return <p>{data.message}</p>;
    }

    return (
      <div className="space-y-6 overflow-x-auto">
        <Card>
          <CardHeader>
            <CardTitle>Services</CardTitle>
          </CardHeader>
          <CardContent>
            {data.Services && data.Services.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Host</TableHead>
                    <TableHead>Port</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>CVEs</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.Services.map((service, index) => (
                    <TableRow key={index}>
                      <TableCell>{service.host}</TableCell>
                      <TableCell>{service.port}</TableCell>
                      <TableCell>{service.protocol}</TableCell>
                      <TableCell>{service.ip}</TableCell>
                      <TableCell>
                        {service.cves && service.cves.length > 0 ? (
                          <ul className="list-disc pl-4">
                            {service.cves.map((cve, cveIndex) => (
                              <li key={cveIndex}>{cve}</li>
                            ))}
                          </ul>
                        ) : (
                          "N/A"
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p>No services found.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Leaks</CardTitle>
          </CardHeader>
          <CardContent>
            {data.Leaks && data.Leaks.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead>Resource ID</TableHead>
                    <TableHead>Open Ports</TableHead>
                    <TableHead>Leak Count</TableHead>
                    <TableHead>Organization</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.Leaks.map((leak, index) => (
                    <TableRow key={index}>
                      <TableCell>{leak.Ip}</TableCell>
                      <TableCell>{leak.resource_id}</TableCell>
                      <TableCell>{leak.open_ports.join(", ")}</TableCell>
                      <TableCell>{leak.leak_count}</TableCell>
                      <TableCell>
                        {leak.network?.organization_name || "N/A"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p>No leaks found.</p>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <form action={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="query">Search Query</Label>
          <Input
            id="query"
            name="query"
            placeholder="Enter domain or IP address"
            required
          />
        </div>
        <Button type="submit" disabled={isPending}>
          {isPending ? "Searching..." : "Search"}
        </Button>
      </form>

      {results && (
        <Card className="p-6">
          <CardHeader>
            <CardTitle>{results.type} Results</CardTitle>
          </CardHeader>
          <CardContent>
            {results.type === "Shodan"
              ? renderShodanResults(results.data)
              : renderLeakXResults(results.data)}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
