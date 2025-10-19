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

interface ExtensionLog {
  id: number;
  url: string;
  timestamp: string;
  type: 'malicious' | 'normal' | 'suspicious';
  reason: string;
}

interface McpLog {
  id: number;
  timestamp: string;
  level: string;
  message: string;
  command?: string;
  tool?: string;
  target?: string;
  log_source: string;
}

type Log = ExtensionLog | McpLog;

interface LogTableProps {
  logs: Log[];
  logSource: 'extension' | 'mcp';
}

const LogTable: React.FC<LogTableProps> = ({ logs = [], logSource }) => {
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

  const getLevelVariant = (level: string): "default" | "destructive" | "success" | "warning" => {
    switch (level.toLowerCase()) {
      case 'error':
        return 'destructive';
      case 'warning':
        return 'warning';
      case 'info':
        return 'success';
      default:
        return 'default';
    }
  };

  const getToolIcon = (tool?: string) => {
    if (!tool) return <ClockIcon className="w-4 h-4" />;
    
    switch (tool.toLowerCase()) {
      case 'nmap':
        return <GlobeAltIcon className="w-4 h-4" />;
      case 'dirb':
      case 'gobuster':
        return <ExclamationTriangleIcon className="w-4 h-4" />;
      case 'hydra':
        return <ExclamationTriangleIcon className="w-4 h-4" />;
      case 'curl':
        return <CheckCircleIcon className="w-4 h-4" />;
      default:
        return <ClockIcon className="w-4 h-4" />;
    }
  };

  const isExtensionLog = (log: Log): log is ExtensionLog => {
    return 'url' in log && 'type' in log;
  };

  const isMcpLog = (log: Log): log is McpLog => {
    return 'level' in log && 'message' in log;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {logSource === 'extension' ? 'Security Events' : 'MCP Logs'}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[80px]">ID</TableHead>
              {logSource === 'extension' ? (
                <>
                  <TableHead className="w-[120px]">Type</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead className="w-[200px]">Reason</TableHead>
                </>
              ) : (
                <>
                  <TableHead className="w-[120px]">Level</TableHead>
                  <TableHead>Tool</TableHead>
                  <TableHead className="w-[200px]">Target</TableHead>
                </>
              )}
              <TableHead className="w-[180px]">Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {!logs || logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  {logSource === 'extension' 
                    ? 'No security events detected. Waiting for activity...'
                    : 'No MCP logs found.'
                  }
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => {
                if (logSource === 'extension' && isExtensionLog(log)) {
                  return (
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
                  );
                } else if (logSource === 'mcp' && isMcpLog(log)) {
                  return (
                    <TableRow 
                      key={log.id} 
                      className="hover:bg-muted/50"
                    >
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        #{log.id}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getLevelVariant(log.level)} className="capitalize flex items-center gap-1 w-fit">
                          {getTypeIcon(log.level)}
                          {log.level}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[300px]">
                        <div className="flex items-center gap-2 truncate">
                          {getToolIcon(log.tool)}
                          <span className="truncate">{log.tool || 'Unknown'}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        <span className="text-foreground" title={log.target || 'No target'}>
                          {log.target || '-'}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        <div className="flex items-center gap-2">
                          <ClockIcon className="w-4 h-4 flex-shrink-0" />
                          <span>{new Date(log.timestamp).toLocaleString()}</span>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                }
                return null;
              })
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};

export default LogTable;
