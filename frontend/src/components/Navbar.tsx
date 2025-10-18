import React, { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import ThemeToggle from "./ThemeToggle";
import { 
  ShieldCheckIcon, 
  ClockIcon, 
} from "@heroicons/react/24/outline";

const Navbar: React.FC = () => {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <nav className="sticky top-0 z-50 border-b border-gray-200 dark:border-gray-800 bg-white/95 dark:bg-gray-900/95 backdrop-blur-md supports-[backdrop-filter]:bg-white/60 dark:supports-[backdrop-filter]:bg-gray-900/60 shadow-sm">
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo and Brand */}
          <div className="flex items-center space-x-4">
            <div className="relative">
              <div className="w-10 h-10 bg-gradient-to-br from-primary to-primary/80 rounded-xl flex items-center justify-center shadow-lg">
                <ShieldCheckIcon className="w-6 h-6 text-primary-foreground" />
              </div>
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-foreground to-foreground/80 bg-clip-text">
                Inspy Security
              </h1>
              <p className="text-sm text-muted-foreground font-medium">
                Advanced threat monitoring
              </p>
            </div>
          </div>
          
          {/* Status and Info */}
          <div className="flex items-center space-x-6">

            {/* Live Status */}
            <Badge variant="success" className="animate-pulse shadow-sm">
              <div className="w-2 h-2 bg-white rounded-full mr-2 animate-ping"></div>
              <span className="font-semibold">Live</span>
            </Badge>

            {/* Current Time */}
            <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 bg-muted/50 rounded-lg">
              <ClockIcon className="w-4 h-4 text-blue-500" />
              <span className="text-sm font-mono font-medium text-muted-foreground">
                {formatTime(currentTime)}
              </span>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center space-x-2">
              <ThemeToggle />
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
