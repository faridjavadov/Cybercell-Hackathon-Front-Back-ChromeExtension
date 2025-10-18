import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type ColorType = "default" | "destructive" | "success" | "warning";

interface StatsCardProps {
  title: string;
  value: number;
  color?: ColorType;
  description?: string;
}

const StatsCard: React.FC<StatsCardProps> = ({ 
  title, 
  value, 
  color = "default",
  description 
}) => {
  const getBorderColor = (color: ColorType): string => {
    switch (color) {
      case "destructive":
        return "border-t-red-500";
      case "success":
        return "border-t-green-500";
      case "warning":
        return "border-t-yellow-500";
      default:
        return "border-t-blue-500";
    }
  };

  return (
    <Card className={`bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 ${getBorderColor(color)} border-t-4 hover:shadow-md transition-all duration-300`}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold text-gray-600 dark:text-gray-400">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="text-3xl font-bold tracking-tight text-gray-900 dark:text-gray-100 mb-2">
          {value.toLocaleString()}
        </div>
        {description && (
          <p className="text-xs text-gray-500 dark:text-gray-500 leading-relaxed">
            {description}
          </p>
        )}
      </CardContent>
    </Card>
  );
};

export default StatsCard;
