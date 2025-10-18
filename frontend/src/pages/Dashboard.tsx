import React, { useEffect, useState } from "react";
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
  type: 'malicious' | 'normal';
  reason: string;
}

interface Stats {
  total_logs: number;
  malicious_logs: number;
  normal_logs: number;
  recent_logs: number;
}

interface PaginatedLogs {
  logs: Log[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

type ConnectionStatus = "connecting" | "connected" | "error";

const Dashboard: React.FC = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [stats, setStats] = useState<Stats>({
    total_logs: 0,
    malicious_logs: 0,
    normal_logs: 0,
    recent_logs: 0
  });
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>("connecting");
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [itemsPerPage] = useState(20);
  const [hasNext, setHasNext] = useState(false);
  const [hasPrev, setHasPrev] = useState(false);
  
  // Filter state
  const [filters, setFilters] = useState({
    log_type: "all",
    reason: "all",
    start_date: "",
    end_date: ""
  });

  useEffect(() => {
    // Fetch initial logs
    fetchLogs();
    fetchStats();

    // Set up SSE connection for real-time updates
    const eventSource = new EventSource("http://localhost:8000/api/logs/stream");
    
    eventSource.onopen = () => {
      setConnectionStatus("connected");
      console.log("SSE connection opened");
    };

    eventSource.onmessage = (event) => {
      try {
        const newLogs: Log[] = JSON.parse(event.data);
        setLogs(newLogs);
        setLastUpdate(new Date());
        // Update stats when new logs arrive
        fetchStats();
      } catch (err) {
        console.error("Error parsing logs:", err);
      }
    };

    eventSource.onerror = () => {
      setConnectionStatus("error");
      console.error("SSE connection error");
    };

    // Cleanup
    return () => {
      eventSource.close();
    };
  }, []);

  const fetchLogs = async (page: number = currentPage, currentFilters = filters): Promise<void> => {
    try {
      // Build query parameters
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: itemsPerPage.toString()
      });
      
      // Add filters to query parameters
      if (currentFilters.log_type && currentFilters.log_type !== "all") {
        params.append("log_type", currentFilters.log_type);
      }
      if (currentFilters.reason && currentFilters.reason !== "all") {
        params.append("reason", currentFilters.reason);
      }
      if (currentFilters.start_date) {
        params.append("start_date", currentFilters.start_date);
      }
      if (currentFilters.end_date) {
        params.append("end_date", currentFilters.end_date);
      }
      
      const response = await fetch(`http://localhost:8000/api/logs?${params.toString()}`);
      if (response.ok) {
        const data: PaginatedLogs = await response.json();
        setLogs(data.logs);
        setTotalPages(data.total_pages);
        setTotalItems(data.total);
        setHasNext(data.has_next);
        setHasPrev(data.has_prev);
        setCurrentPage(data.page);
        setLastUpdate(new Date());
      }
    } catch (error) {
      console.error("Error fetching logs:", error);
    }
  };

  const fetchStats = async (): Promise<void> => {
    try {
      const response = await fetch("http://localhost:8000/api/logs/stats");
      if (response.ok) {
        const data: Stats = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error("Error fetching stats:", error);
    }
  };

  const handleRefresh = async (): Promise<void> => {
    setIsRefreshing(true);
    try {
      await Promise.all([fetchLogs(currentPage), fetchStats()]);
    } finally {
      setTimeout(() => setIsRefreshing(false), 1000);
    }
  };

  const handlePageChange = async (page: number): Promise<void> => {
    await fetchLogs(page, filters);
  };

  const handleFiltersChange = (newFilters: typeof filters): void => {
    setFilters(newFilters);
    setCurrentPage(1); // Reset to first page when filters change
    fetchLogs(1, newFilters);
  };

  const handleClearFilters = (): void => {
    const clearedFilters = {
      log_type: "all",
      reason: "all",
      start_date: "",
      end_date: ""
    };
    setFilters(clearedFilters);
    setCurrentPage(1);
    fetchLogs(1, clearedFilters);
  };

  const getConnectionStatusVariant = (): "default" | "destructive" | "success" | "warning" => {
    switch (connectionStatus) {
      case "connected":
        return "success";
      case "error":
        return "destructive";
      default:
        return "warning";
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
                <Badge variant={getConnectionStatusVariant()} className="animate-pulse">
                  <div className="w-2 h-2 bg-current rounded-full mr-2"></div>
                  {connectionStatus === "connected" ? "Connected" : 
                   connectionStatus === "error" ? "Connection Error" : "Connecting..."}
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
          <div className="transform transition-all duration-300 hover:scale-105">
            <StatsCard
              title="Total Events"
              value={stats.total_logs}
              color="default"
              description="All security events"
            />
          </div>
          <div className="transform transition-all duration-300 hover:scale-105">
            <StatsCard
              title="Threats Detected"
              value={stats.malicious_logs}
              color="destructive"
              description="Malicious activities"
            />
          </div>
          <div className="transform transition-all duration-300 hover:scale-105">
            <StatsCard
              title="Safe Events"
              value={stats.normal_logs}
              color="success"
              description="Normal activities"
            />
          </div>
          <div className="transform transition-all duration-300 hover:scale-105">
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
                    <span className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></span>
                    Security Events
                  </CardTitle>
                  <CardDescription className="text-base mt-2">
                    Live monitoring of file uploads and security threats
                  </CardDescription>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant="outline" className="text-xs">
                    {totalItems} total events
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
                  currentPage={currentPage}
                  totalPages={totalPages}
                  hasNext={hasNext}
                  hasPrev={hasPrev}
                  onPageChange={handlePageChange}
                  totalItems={totalItems}
                  itemsPerPage={itemsPerPage}
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
