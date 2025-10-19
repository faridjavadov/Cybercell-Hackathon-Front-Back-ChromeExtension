import React, { useState } from "react";
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
import {
  FunnelIcon,
  ChevronDownIcon,
  ChevronUpIcon
} from "@heroicons/react/24/outline";

interface LogsFilterProps {
  onFiltersChange: (filters: {
    log_type: string;
    reason: string;
    start_date: string;
    end_date: string;
  }) => void;
  onClearFilters: () => void;
  onLogSourceChange: (source: string) => void;
  currentLogSource: string;
}

const LogsFilter: React.FC<LogsFilterProps> = ({ 
  onLogSourceChange, 
  currentLogSource = "extension"
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <Card className="mb-6 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FunnelIcon className="w-5 h-5 text-muted-foreground" />
            <CardTitle className="text-lg">Filters</CardTitle>
            <Badge variant="secondary" className="ml-2">
              {currentLogSource === "extension" ? "Extension" : "MCP"}
            </Badge>
          </div>
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
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium flex items-center gap-2">
              <FunnelIcon className="w-4 h-4" />
              Log Source
            </label>
            <Select
              value={currentLogSource}
              onValueChange={onLogSourceChange}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select log source" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="extension">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-blue-500" />
                    Extension Logs
                  </div>
                </SelectItem>
                <SelectItem value="mcp">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-purple-500" />
                    MCP Logs
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      )}
    </Card>
  );
};

export default LogsFilter;
