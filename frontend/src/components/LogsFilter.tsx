import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import DateRangePicker from "@/components/ui/date-range-picker";
import {
  FunnelIcon,
  XMarkIcon,
  CalendarIcon,
  TagIcon,
  ChevronDownIcon,
  ChevronUpIcon
} from "@heroicons/react/24/outline";

interface FilterOptions {
  types: string[];
  reasons: string[];
  date_range: {
    min: string | null;
    max: string | null;
  };
}

interface LogsFilterProps {
  onFiltersChange: (filters: {
    log_type: string;
    reason: string;
    start_date: string;
    end_date: string;
  }) => void;
  onClearFilters: () => void;
}

const LogsFilter: React.FC<LogsFilterProps> = ({ onFiltersChange, onClearFilters }) => {
  const [filters, setFilters] = useState({
    log_type: "all",
    reason: "all",
    start_date: "",
    end_date: ""
  });
  
  const [filterOptions, setFilterOptions] = useState<FilterOptions>({
    types: [],
    reasons: [],
    date_range: { min: null, max: null }
  });
  
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeFiltersCount, setActiveFiltersCount] = useState(0);

  useEffect(() => {
    fetchFilterOptions();
  }, []);

  useEffect(() => {
    // Count active filters
    const count = Object.values(filters).filter(value => 
      value !== "all" && value !== ""
    ).length;
    setActiveFiltersCount(count);
    
    // Apply filters
    onFiltersChange(filters);
  }, [filters, onFiltersChange]);

  const fetchFilterOptions = async () => {
    try {
      const response = await fetch("http://localhost:8000/api/logs/filter-options");
      if (response.ok) {
        const data = await response.json();
        setFilterOptions(data);
      }
    } catch (error) {
      console.error("Error fetching filter options:", error);
    }
  };

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleClearFilters = () => {
    setFilters({
      log_type: "all",
      reason: "all",
      start_date: "",
      end_date: ""
    });
    onClearFilters();
  };


  return (
    <Card className="mb-6 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FunnelIcon className="w-5 h-5 text-muted-foreground" />
            <CardTitle className="text-lg">Filters</CardTitle>
            {activeFiltersCount > 0 && (
              <Badge variant="secondary" className="ml-2">
                {activeFiltersCount} active
              </Badge>
            )}
          </div>
          <div className="flex items-center space-x-2">
            {activeFiltersCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleClearFilters}
                className="text-muted-foreground hover:text-foreground"
              >
                <XMarkIcon className="w-4 h-4 mr-1" />
                Clear All
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
              className="h-8 w-8 p-0"
            >
              {isExpanded ? (
                <ChevronUpIcon className="w-4 h-4" />
              ) : (
                <ChevronDownIcon className="w-4 h-4" />
              )}
            </Button>
          </div>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Type Filter */}
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <TagIcon className="w-4 h-4" />
                Type
              </label>
              <Select
                value={filters.log_type}
                onValueChange={(value) => handleFilterChange("log_type", value)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="All types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  {filterOptions.types.map((type) => (
                    <SelectItem key={type} value={type}>
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${
                          type === 'malicious' ? 'bg-red-500' : 'bg-green-500'
                        }`} />
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Reason Filter */}
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <FunnelIcon className="w-4 h-4" />
                Reason
              </label>
              <Select
                value={filters.reason}
                onValueChange={(value) => handleFilterChange("reason", value)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="All reasons" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Reasons</SelectItem>
                  {filterOptions.reasons.map((reason) => (
                    <SelectItem key={reason} value={reason}>
                      {reason}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Date Range Filter */}
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <CalendarIcon className="w-4 h-4" />
                Date Range
              </label>
              <DateRangePicker
                startDate={filters.start_date}
                endDate={filters.end_date}
                onStartDateChange={(date: string) => {
                  setFilters(prev => ({
                    ...prev,
                    start_date: date
                  }));
                }}
                onEndDateChange={(date: string) => {
                  setFilters(prev => ({
                    ...prev,
                    end_date: date
                  }));
                }}
              />
            </div>
          </div>

          {/* Quick Date Filters */}
          <div className="flex flex-wrap gap-2 pt-2 border-t">
            <span className="text-sm text-muted-foreground mr-2">Quick filters:</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                const now = new Date();
                const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                setFilters(prev => ({
                  ...prev,
                  start_date: last24h.toISOString(),
                  end_date: now.toISOString()
                }));
              }}
            >
              Last 24h
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                const now = new Date();
                const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                setFilters(prev => ({
                  ...prev,
                  start_date: last7d.toISOString(),
                  end_date: now.toISOString()
                }));
              }}
            >
              Last 7 days
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                const now = new Date();
                const last30d = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                setFilters(prev => ({
                  ...prev,
                  start_date: last30d.toISOString(),
                  end_date: now.toISOString()
                }));
              }}
            >
              Last 30 days
            </Button>
          </div>
        </CardContent>
      )}
    </Card>
  );
};

export default LogsFilter;
