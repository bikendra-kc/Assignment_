import React, { useEffect } from "react";
import { getUserLogHistory } from "../../redux/actions/user";
import { useDispatch, useSelector } from "react-redux";

const LogHistoryComponent = () => {
  const dispatch = useDispatch();
  const { userLog } = useSelector((state) => state.user);

  useEffect(() => {
    // Dispatch the action to get user log history
    dispatch(getUserLogHistory());
  }, [dispatch]);

  return (
    <div className="w-full px-5">
      <h2 className="block text-[25px] text-center font-[600] text-[#000000ba] pb-2">
        Log History
      </h2>
      <ul className="w-full max-w-md mx-auto overflow-y-auto max-h-[400px]">
        {userLog &&
          userLog.map((log, index) => (
            <li key={index} className="mb-4">
              <div className="border rounded p-4 bg-white shadow">
                <p className="mb-2">
                  <strong>Message:</strong> {log.message}
                </p>
                
                <p>
                  <strong>Date:</strong>{" "}
                  {new Date(log.timestamp).toLocaleString()}
                </p>
                {/* Add more details as needed */}
              </div>
            </li>
          ))}
      </ul>
    </div>
  );
};

export default LogHistoryComponent;
