import React from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  ExclamationTriangleIcon, 
  CheckCircleIcon, 
  ClockIcon,
  GlobeAltIcon 
} from "@heroicons/react/24/outline";

interface Log {
  id: number;
  url: string;
  timestamp: string;
  type: 'malicious' | 'normal' | 'suspicious';
  reason: string;
}

interface LogTableProps {
  logs: Log[];
}

const LogTable: React.FC<LogTableProps> = ({ logs }) => {
  const getTypeVariant = (type: string): "default" | "destructive" | "success" | "warning" => {
    switch (type) {
      case 'malicious':
        return 'destructive';
      case 'normal':
        return 'success';
      case 'suspicious':
        return 'warning';
      default:
        return 'warning';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'malicious':
        return <ExclamationTriangleIcon className="w-4 h-4" />;
      case 'normal':
        return <CheckCircleIcon className="w-4 h-4" />;
      case 'suspicious':
        return <ExclamationTriangleIcon className="w-4 h-4" />;
      default:
        return <ClockIcon className="w-4 h-4" />;
    }
  };

  const formatUrl = (url: string): string => {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Security Events</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[80px]">ID</TableHead>
              <TableHead className="w-[120px]">Type</TableHead>
              <TableHead>URL</TableHead>
              <TableHead className="w-[200px]">Reason</TableHead>
              <TableHead className="w-[180px]">Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  No security events detected. Waiting for activity...
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow 
                  key={log.id} 
                  className={`hover:bg-muted/50 ${
                    log.type === 'suspicious' ? 'bg-yellow-50 dark:bg-yellow-900/20' : ''
                  }`}
                >
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    #{log.id}
                  </TableCell>
                      <TableCell>
                        <Badge variant={getTypeVariant(log.type)} className="capitalize flex items-center gap-1 w-fit">
                          {getTypeIcon(log.type)}
                          {log.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[300px]">
                        <div className="flex items-center gap-2 truncate" title={log.url}>
                          <GlobeAltIcon className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                          <span className="truncate">{formatUrl(log.url)}</span>
                        </div>
                      </TableCell>
                  <TableCell className="text-sm">
                    {log.reason === 'None' ? (
                      <span className="text-muted-foreground">-</span>
                    ) : (
                      <span className="text-foreground">{log.reason}</span>
                    )}
                  </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        <div className="flex items-center gap-2">
                          <ClockIcon className="w-4 h-4 flex-shrink-0" />
                          <span>{new Date(log.timestamp).toLocaleString()}</span>
                        </div>
                      </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};

export default LogTable;
