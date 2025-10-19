import React, { useEffect, useState, useCallback, useRef } from "react";
import LogTable from "../components/LogTable";
import StatsCard from "../components/StatsCard";
import LogsPagination from "../components/LogsPagination";
import LogsFilter from "../components/LogsFilter";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  ArrowPathIcon, 
  DocumentArrowDownIcon,
} from "@heroicons/react/24/outline";

interface Log {
  id: number;
  url: string;
  timestamp: string;
  type: 'malicious' | 'normal' | 'suspicious';
  reason: string;
}

interface Stats {
  total_logs: number;
  malicious_logs: number;
  normal_logs: number;
  recent_logs: number;
}

interface PaginationState {
  page: number;
  per_page: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

interface Filters {
  log_type: string;
  reason: string;
  start_date: string;
  end_date: string;
}

type ConnectionStatus = "connecting" | "connected" | "error" | "disconnected";

const API_BASE_URL = "http://localhost:8000";

const Dashboard: React.FC = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [stats, setStats] = useState<Stats>({
    total_logs: 0,
    malicious_logs: 0,
    normal_logs: 0,
    recent_logs: 0
  });
  const [pagination, setPagination] = useState<PaginationState>({
    page: 1,
    per_page: 20,
    total: 0,
    total_pages: 1,
    has_next: false,
    has_prev: false
  });
  const [filters, setFilters] = useState<Filters>({
    log_type: "all",
    reason: "all",
    start_date: "",
    end_date: ""
  });
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>("connecting");
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [statsUpdated, setStatsUpdated] = useState(false);

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);

  const buildSSEUrl = useCallback((page: number, currentFilters: Filters): string => {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: pagination.per_page.toString()
    });

    if (currentFilters.log_type !== "all") {
      params.append("log_type", currentFilters.log_type);
    }
    if (currentFilters.reason !== "all") {
      params.append("reason", currentFilters.reason);
    }
    if (currentFilters.start_date) {
      params.append("start_date", currentFilters.start_date);
    }
    if (currentFilters.end_date) {
      params.append("end_date", currentFilters.end_date);
    }

    return `${API_BASE_URL}/api/logs/stream?${params.toString()}`;
  }, [pagination.per_page]);

  const connectSSE = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    try {
      setConnectionStatus("connecting");
      const sseUrl = buildSSEUrl(pagination.page, filters);

      const eventSource = new EventSource(sseUrl);
      eventSourceRef.current = eventSource;

      eventSource.onopen = () => {
        setConnectionStatus("connected");
        reconnectAttemptsRef.current = 0;
      };

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          switch (data.type) {
            case 'heartbeat':
              setLastUpdate(new Date());
              break;
              
            case 'error':
              setConnectionStatus("error");
              break;
              
            case 'stats':
              setStats({
                total_logs: data.total_logs,
                malicious_logs: data.malicious_logs,
                normal_logs: data.normal_logs,
                recent_logs: data.recent_logs
              });
              setLastUpdate(new Date());
              
              // Visual feedback
              setStatsUpdated(true);
              setTimeout(() => setStatsUpdated(false), 1000);
              break;
              
            case 'logs':
              setLogs(data.logs);
              setPagination(prev => ({
                ...prev,
                page: data.pagination.page,
                total: data.pagination.total,
                total_pages: data.pagination.total_pages,
                has_next: data.pagination.has_next,
                has_prev: data.pagination.has_prev
              }));
              setLastUpdate(new Date());
              break;
          }
        } catch (error) {
          console.error("Error parsing SSE data:", error);
        }
      };

      eventSource.onerror = () => {
        if (eventSource.readyState === EventSource.CLOSED) {
          setConnectionStatus("disconnected");
        } else {
          setConnectionStatus("error");
        }

        const maxAttempts = 5;
        if (reconnectAttemptsRef.current < maxAttempts) {
          reconnectAttemptsRef.current++;
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectTimeoutRef.current = window.setTimeout(connectSSE, delay);
        } else {
          setConnectionStatus("error");
        }
      };

    } catch (error) {
      setConnectionStatus("error");
    }
  }, [buildSSEUrl, pagination.page, filters]);

  useEffect(() => {
    connectSSE();
    
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connectSSE]);

  const handlePageChange = useCallback((page: number) => {
    setPagination(prev => ({ ...prev, page }));
  }, []);

  const handleFiltersChange = useCallback((newFilters: Filters) => {
    setFilters(newFilters);
    setPagination(prev => ({ ...prev, page: 1 }));
  }, []);

  const handleClearFilters = useCallback(() => {
    const clearedFilters: Filters = {
      log_type: "all",
      reason: "all",
      start_date: "",
      end_date: ""
    };
    setFilters(clearedFilters);
    setPagination(prev => ({ ...prev, page: 1 }));
  }, []);

  const handleRefresh = useCallback(() => {
    setIsRefreshing(true);
    connectSSE();
    setTimeout(() => setIsRefreshing(false), 1000);
  }, [connectSSE]);

  const getConnectionStatusVariant = (): "default" | "destructive" | "success" | "warning" => {
    switch (connectionStatus) {
      case "connected": return "success";
      case "error":
      case "disconnected": return "destructive";
      case "connecting": return "warning";
      default: return "default";
    }
  };

  const getConnectionStatusText = (): string => {
    switch (connectionStatus) {
      case "connected": return "Live";
      case "error": return "Error";
      case "disconnected": return "Disconnected";
      case "connecting": return "Connecting...";
      default: return "Unknown";
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <div className="container mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div className="space-y-2">
              <h1 className="text-4xl font-bold tracking-tight bg-gradient-to-r from-foreground via-foreground to-foreground/80 bg-clip-text">
                Security Dashboard
              </h1>
              <p className="text-lg text-muted-foreground">
                Real-time threat monitoring and analysis
              </p>
              <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                <span>Last updated: {lastUpdate.toLocaleTimeString()}</span>
                <Badge 
                  variant={getConnectionStatusVariant()} 
                  className={connectionStatus === "connected" ? "animate-pulse" : ""}
                >
                  <div className="w-2 h-2 bg-current rounded-full mr-2"></div>
                  {getConnectionStatusText()}
                </Badge>
              </div>
            </div>
            
            {/* Quick Actions */}
            <div className="flex items-center space-x-3">
              <Button 
                onClick={handleRefresh} 
                variant="outline" 
                size="sm"
                disabled={isRefreshing}
                className="min-w-[120px]"
              >
                {isRefreshing ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin mr-2" />
                    Refreshing...
                  </>
                ) : (
                  <>
                    <ArrowPathIcon className="w-4 h-4 mr-2" />
                    Refresh Data
                  </>
                )}
              </Button>
              <Button variant="outline" size="sm">
                <DocumentArrowDownIcon className="w-4 h-4 mr-2" />
                Export
              </Button>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className={`transform transition-all duration-300 hover:scale-105 ${statsUpdated ? 'ring-2 ring-blue-500' : ''}`}>
            <StatsCard
              title="Total Events"
              value={stats.total_logs}
              color="default"
              description="All security events"
            />
          </div>
          <div className={`transform transition-all duration-300 hover:scale-105 ${statsUpdated ? 'ring-2 ring-red-500' : ''}`}>
            <StatsCard
              title="Threats Detected"
              value={stats.malicious_logs}
              color="destructive"
              description="Malicious activities"
            />
          </div>
          <div className={`transform transition-all duration-300 hover:scale-105 ${statsUpdated ? 'ring-2 ring-green-500' : ''}`}>
            <StatsCard
              title="Safe Events"
              value={stats.normal_logs}
              color="success"
              description="Normal activities"
            />
          </div>
          <div className={`transform transition-all duration-300 hover:scale-105 ${statsUpdated ? 'ring-2 ring-yellow-500' : ''}`}>
            <StatsCard
              title="Recent Activity"
              value={stats.recent_logs}
              color="warning"
              description="Last 24 hours"
            />
          </div>
        </div>

        {/* Filters */}
        <LogsFilter
          onFiltersChange={handleFiltersChange}
          onClearFilters={handleClearFilters}
        />

        {/* Logs Table */}
        <div className="space-y-6">
          <Card className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 shadow-lg">
            <CardHeader className="pb-4">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-2xl font-bold tracking-tight flex items-center gap-3">
                    <span className={`w-2 h-2 rounded-full ${connectionStatus === 'connected' ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`}></span>
                    Security Events
                  </CardTitle>
                  <CardDescription className="text-base mt-2">
                    Live monitoring of file uploads and security threats (Page {pagination.page} of {pagination.total_pages})
                  </CardDescription>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant="outline" className="text-xs">
                    {pagination.total} total events
                  </Badge>
                  <Button 
                    onClick={handleRefresh} 
                    variant="ghost" 
                    size="sm"
                    disabled={isRefreshing}
                  >
                    {isRefreshing ? (
                      <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    ) : (
                      <ArrowPathIcon className="w-4 h-4" />
                    )}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <LogTable logs={logs} />
              <div className="px-6">
                <LogsPagination
                  currentPage={pagination.page}
                  totalPages={pagination.total_pages}
                  hasNext={pagination.has_next}
                  hasPrev={pagination.has_prev}
                  onPageChange={handlePageChange}
                  totalItems={pagination.total}
                  itemsPerPage={pagination.per_page}
                />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;