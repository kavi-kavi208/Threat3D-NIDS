import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { WebSocketProvider } from './context/WebSocketContext';
import { LanguageProvider } from './context/LanguageContext';
import { VoiceProvider } from './context/VoiceContext';
import { Layout } from './components/layout/Layout';
import { ProtectedRoute } from './components/common/ProtectedRoute';

import { LoginPage } from './pages/LoginPage';
import { LearningPage } from './pages/LearningPage';
import { DashboardPage } from './pages/DashboardPage';
import { TopologyPage } from './pages/TopologyPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { SimulationPage } from './pages/SimulationPage';
import { TrafficPage } from './pages/TrafficPage';
import { RulesPage } from './pages/RulesPage';
import { NotFoundPage } from './pages/NotFoundPage';

export function App() {
  return (
    <LanguageProvider>
      <AuthProvider>
        <WebSocketProvider>
          <BrowserRouter>
            <VoiceProvider>
          <Routes>
            {/* Public Authentication Route */}
            <Route path="/login" element={<LoginPage />} />

            {/* Protected SOC Routes under Shell Layout */}
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<DashboardPage />} />
              <Route path="topology" element={<TopologyPage />} />
              <Route path="threats" element={<ThreatsPage />} />
              <Route
                path="simulation"
                element={
                  <ProtectedRoute allowedRoles={['ROLE_ADMIN', 'ROLE_ANALYST']}>
                    <SimulationPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="traffic"
                element={
                  <ProtectedRoute allowedRoles={['ROLE_ADMIN', 'ROLE_ANALYST']}>
                    <TrafficPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="rules"
                element={
                  <ProtectedRoute allowedRoles={['ROLE_ADMIN', 'ROLE_ANALYST']}>
                    <RulesPage />
                  </ProtectedRoute>
                }
              />
              <Route path="learning" element={<LearningPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
            </VoiceProvider>
        </BrowserRouter>
      </WebSocketProvider>
    </AuthProvider>
    </LanguageProvider>
  );
}

export default App;
