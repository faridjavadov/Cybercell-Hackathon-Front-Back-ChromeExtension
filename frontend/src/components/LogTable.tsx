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

  // Extract HTTP method from command
  const getHttpMethod = (command?: string): string | null => {
    if (!command) return null;
    const methodMatch = command.match(/-X\s+(\w+)/i);
    return methodMatch ? methodMatch[1].toUpperCase() : null;
  };

  // Extract URL/endpoint from command
  const getEndpoint = (command?: string): string | null => {
    if (!command) return null;
    const urlMatch = command.match(/https?:\/\/[^\s]+/);
    return urlMatch ? urlMatch[0] : null;
  };

  // Extract port from command
  const getPort = (command?: string): string | null => {
    if (!command) return null;
    const portMatch = command.match(/-p\s+(\d+(?:-\d+)?)/);
    return portMatch ? portMatch[1] : null;
  };

  // Format command for display, using message as fallback
  const formatCommand = (command?: string, message?: string): string => {
    const text = command || message || '';
    if (!text) return '-';
    
    // For curl commands, show method and endpoint
    if (text.includes('curl')) {
      const method = getHttpMethod(text);
      const endpoint = getEndpoint(text);
      if (method && endpoint) {
        return `${method} ${endpoint}`;
      } else if (endpoint) {
        return `GET ${endpoint}`;
      }
    }
    
    // For nmap commands, show tool and target
    if (text.includes('nmap')) {
      const target = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      const port = getPort(text);
      if (target) {
        return port ? `nmap ${target[0]}:${port}` : `nmap ${target[0]}`;
      }
    }
    
    // For hydra commands, show tool and target
    if (text.includes('hydra')) {
      const target = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      if (target) {
        return `hydra ${target[0]}`;
      }
    }
    
    // For gobuster commands, show tool and target
    if (text.includes('gobuster')) {
      const endpoint = getEndpoint(text);
      if (endpoint) {
        return `gobuster ${endpoint}`;
      }
    }
    
    // For HTTP request logs in message, extract method and endpoint
    const httpInfo = parseHttpLog(text);
    if (httpInfo.method && httpInfo.endpoint) {
      return `${httpInfo.method} ${httpInfo.endpoint}`;
    }
    
    // For other commands, show first part
    const parts = text.split(' ');
    return parts.length > 3 ? `${parts[0]} ${parts[1]}...` : text;
  };

  // Extract HTTP method and endpoint from HTTP request logs
  const parseHttpLog = (message?: string): { method?: string; endpoint?: string } => {
    if (!message) return {};
    const httpMatch = message.match(/"(\w+)\s+([^\s]+)\s+HTTP\/1\.1"/);
    if (httpMatch) {
      return {
        method: httpMatch[1],
        endpoint: httpMatch[2]
      };
    }
    return {};
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
                  <TableHead>Command</TableHead>
                  <TableHead className="w-[200px]">Target/Endpoint</TableHead>
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
                  // Check if this is an HTTP request log (no command but has HTTP pattern in message)
                  const httpInfo = parseHttpLog(log.message);
                  const isHttpLog = !log.command && httpInfo.method;
                  
                  // Determine tool from command or message
                  const toolText = log.command || log.message || '';
                  const detectedTool = log.tool || 
                    (toolText.includes('curl') ? 'curl' :
                     toolText.includes('nmap') ? 'nmap' :
                     toolText.includes('hydra') ? 'hydra' :
                     toolText.includes('gobuster') ? 'gobuster' :
                     toolText.includes('dirb') ? 'dirb' : null);
                  
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
                        <div className="flex items-center gap-2 truncate" title={log.command || log.message}>
                          {isHttpLog ? (
                            <CheckCircleIcon className="w-4 h-4 text-green-500" />
                          ) : (
                            getToolIcon(detectedTool)
                          )}
                          <span className="truncate font-mono text-sm">
                            {formatCommand(log.command, log.message)}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        <div className="flex flex-col gap-1">
                          {log.target && (
                            <span className="text-foreground font-mono text-xs" title={log.target}>
                              {log.target}
                            </span>
                          )}
                          {getEndpoint(log.command || log.message) && (
                            <span className="text-blue-600 dark:text-blue-400 font-mono text-xs" title={getEndpoint(log.command || log.message)}>
                              {getEndpoint(log.command || log.message)}
                            </span>
                          )}
                          {isHttpLog && httpInfo.endpoint && (
                            <span className="text-green-600 dark:text-green-400 font-mono text-xs" title={httpInfo.endpoint}>
                              {httpInfo.endpoint}
                            </span>
                          )}
                          {!log.target && !getEndpoint(log.command || log.message) && !isHttpLog && (
                            <span className="text-muted-foreground">-</span>
                          )}
                        </div>
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
