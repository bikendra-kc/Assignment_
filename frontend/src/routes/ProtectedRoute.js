import { useSelector } from "react-redux";
import { Navigate } from "react-router-dom";

const ProtectedRoute = ({ children }) => {
  const { loading, isAuthenticated } = useSelector((state) => state.user);
  if (loading === false) {
    if (!isAuthenticated) {
      return <Navigate to="/login" replace />;
    }
    return children;
  }
};

export default ProtectedRoute;
// This is the protected route section which help to protect route by checking the user state to reduct so after attempting to enter unauthorized URL then it will check if the user in server. If it is authorized then it will give permission to access page 